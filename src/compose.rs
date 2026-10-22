//! `lx compose [-f file] up|down|ps|logs [service]`: the multi-container apps of a compose file.
//!
//! Each service becomes `lx run -d --name <project>-<service>`, started in depends_on order. lx containers
//! share the host's network, so a service reaches another by name through an /etc/hosts line
//! (`--add-host db:127.0.0.1`) and its usual port. Keys: image, build (a path or {context, dockerfile}),
//! ports, environment (map or list), volumes (a relative host path, or a named volume kept in
//! rootfs/volumes/<project>_<name>), command, entrypoint, working_dir, user, depends_on.
//! `up` follows the services' output until they end or Ctrl-C (then stops them); `up -d` leaves them running.
//! ponytail: no networks, profiles, env_file,
//! healthchecks or restart policies; services' ports must not collide (one network for all).

use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub fn compose(args: &[String]) -> Result<(), String> {
    // Our own std handles (a shell's pipe) must not leak into the containers we start: a detached one
    // would hold that pipe open forever, and whoever reads our output would wait for it. Children still
    // get their std handles explicitly.
    for std in [-10i32, -11, -12] {
        unsafe { crate::win::SetHandleInformation(crate::win::GetStdHandle(std as u32), 1, 0) };
    }
    let (file, rest) = match args {
        [f, file, rest @ ..] if f == "-f" || f == "--file" => (PathBuf::from(file), rest),
        _ => (["compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"].iter().map(PathBuf::from)
            .find(|p| p.exists()).unwrap_or_else(|| PathBuf::from("compose.yaml")), args),
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let doc = yaml(&text)?;
    let dir = std::fs::canonicalize(file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
        .map_err(|e| e.to_string())?;
    let project: String = dir.file_name().unwrap_or_default().to_string_lossy().to_lowercase()
        .chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    let services = doc["services"].as_object().ok_or("the compose file has no services")?;
    let order = start_order(services)?;
    let lx = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = |svc: &str| format!("{project}-{svc}");
    match rest {
        [cmd, ..] if cmd == "up" => {
            let mut pids = Vec::new();
            for svc in &order {
                let s = &services[svc];
                let image = match &s["build"] {
                    Value::Null => s["image"].as_str().ok_or(format!("{svc}: needs image or build"))?.to_string(),
                    b => {
                        let ctx = dir.join(b.as_str().or(b["context"].as_str()).unwrap_or("."));
                        let tag = s["image"].as_str().map(String::from).unwrap_or(format!("{}:latest", name(svc)));
                        let mut c = std::process::Command::new(&lx);
                        c.args(["build", "-t", &tag]);
                        if let Some(f) = b["dockerfile"].as_str() {
                            c.arg("-f").arg(ctx.join(f));
                        }
                        if !c.arg(&ctx).status().map_err(|e| e.to_string())?.success() {
                            return Err(format!("{svc}: build failed"));
                        }
                        tag
                    }
                };
                let mut c = std::process::Command::new(&lx);
                c.args(["run", "-d", "--name", &name(svc)]);
                for other in services.keys() {
                    c.args(["--add-host", &format!("{other}:127.0.0.1")]);
                }
                for p in list(&s["ports"]) {
                    c.args(["-p", &p]);
                }
                for e in env_list(&s["environment"]) {
                    c.args(["-e", &e]);
                }
                for v in list(&s["volumes"]) {
                    c.args(["-v", &volume(&v, &dir, &project)?]);
                }
                for (key, flag) in [("working_dir", "-w"), ("user", "-u")] {
                    if let Some(x) = s[key].as_str() {
                        c.args([flag, x]);
                    }
                }
                if !s["entrypoint"].is_null() {
                    c.args(["--entrypoint", &words(&s["entrypoint"]).join(" ")]);
                }
                c.arg(&image).args(words(&s["command"]));
                let out = c.output().map_err(|e| e.to_string())?;
                if !out.status.success() {
                    return Err(format!("{svc}: {}", String::from_utf8_lossy(&out.stderr).trim()));
                }
                let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
                println!("started {} (pid {pid})", name(svc));
                pids.push((svc.clone(), pid.parse::<u32>().ok()));
            }
            if rest.iter().any(|a| a == "-d" || a == "--detach") {
                return Ok(());
            }
            // In the foreground, like `docker compose up`: follow every service's output until they've all
            // ended or Ctrl-C, then stop them.
            follow(&pids);
            for svc in order.iter().rev() {
                let _ = std::process::Command::new(&lx).args(["stop", &name(svc)]).output();
            }
            Ok(())
        }
        [cmd, ..] if cmd == "down" => {
            for svc in order.iter().rev() {
                let _ = std::process::Command::new(&lx).args(["stop", &name(svc)]).output();
                println!("stopped {}", name(svc));
            }
            Ok(())
        }
        [cmd] if cmd == "ps" => {
            println!("{:<24} PID", "SERVICE");
            for svc in &order {
                let pid = crate::proc::container_pid(&name(svc)).filter(|p| crate::proc::name_of(*p).is_some());
                println!("{svc:<24} {}", pid.map_or("-".into(), |p| p.to_string()));
            }
            Ok(())
        }
        [cmd, which @ ..] if cmd == "logs" => {
            for svc in order.iter().filter(|s| which.is_empty() || which.contains(s)) {
                let Some(pid) = crate::proc::container_pid(&name(svc)) else { continue };
                if let Some(log) = crate::proc::log_of(pid) {
                    for line in std::fs::read_to_string(log).unwrap_or_default().lines() {
                        println!("{svc} | {line}");
                    }
                }
            }
            Ok(())
        }
        _ => Err("usage: lx compose [-f file] up [-d]|down|ps|logs [service...]".into()),
    }
}

static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(_kind: u32) -> i32 {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
    1 // handled: we stop the services ourselves
}

/// Print each service's new log lines as `service | line` until every service has ended or Ctrl-C.
fn follow(services: &[(String, Option<u32>)]) {
    use std::io::{Read, Seek, SeekFrom, Write};
    unsafe { crate::win::SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    let mut offsets = vec![0u64; services.len()];
    let mut partial = vec![String::new(); services.len()];
    loop {
        let mut running = 0;
        for (i, (svc, pid)) in services.iter().enumerate() {
            let Some(pid) = *pid else { continue };
            if crate::proc::send(pid, 0).is_ok() {
                running += 1;
            }
            let Some(mut f) = crate::proc::log_of(pid).and_then(|p| std::fs::File::open(p).ok()) else { continue };
            let mut buf = Vec::new();
            if f.seek(SeekFrom::Start(offsets[i])).is_ok() && f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                offsets[i] += buf.len() as u64;
                partial[i].push_str(&String::from_utf8_lossy(&buf));
                while let Some(nl) = partial[i].find('\n') {
                    let line: String = partial[i].drain(..=nl).collect();
                    let _ = write!(std::io::stdout(), "{svc} | {line}");
                }
            }
        }
        let _ = std::io::stdout().flush();
        if running == 0 || INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Services in an order where each comes after what it depends_on.
fn start_order(services: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut order: Vec<String> = Vec::new();
    fn visit(s: &str, all: &Map<String, Value>, order: &mut Vec<String>, path: &mut Vec<String>) -> Result<(), String> {
        if order.iter().any(|o| o == s) {
            return Ok(());
        }
        if path.iter().any(|p| p == s) {
            return Err(format!("depends_on cycle through {s}"));
        }
        path.push(s.to_string());
        let deps = &all.get(s).ok_or(format!("depends_on names an unknown service {s}"))?["depends_on"];
        let deps: Vec<String> = deps.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_else(|| list(deps));
        for d in deps {
            visit(&d, all, order, path)?;
        }
        path.pop();
        order.push(s.to_string());
        Ok(())
    }
    for s in services.keys() {
        visit(s, services, &mut order, &mut Vec::new())?;
    }
    Ok(order)
}

fn list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(scalar).collect(),
        Value::Null => vec![],
        x => vec![scalar(x)],
    }
}

fn scalar(v: &Value) -> String {
    v.as_str().map(String::from).unwrap_or_else(|| v.to_string())
}

/// `command:`/`entrypoint:` as a list (exec form) or a string, split like a shell would (quotes group,
/// `""` is an empty argument), as compose does.
fn words(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(scalar).collect(),
        Value::Null => vec![],
        x => {
            let (mut out, mut cur, mut quote, mut any) = (Vec::new(), String::new(), None, false);
            for c in scalar(x).chars() {
                match (c, quote) {
                    ('"' | '\'', None) => (quote, any) = (Some(c), true),
                    (q, Some(o)) if q == o => quote = None,
                    (c, None) if c.is_whitespace() => {
                        if any {
                            out.push(std::mem::take(&mut cur));
                        }
                        any = false;
                    }
                    (c, _) => (cur.push(c), any = true).0,
                }
            }
            if any {
                out.push(cur);
            }
            out
        }
    }
}

fn env_list(v: &Value) -> Vec<String> {
    match v {
        Value::Object(m) => m.iter().map(|(k, v)| format!("{k}={}", scalar(v))).collect(),
        _ => list(v),
    }
}

/// `./data:/data[:ro]` (relative to the compose file) or `name:/path` (a named volume, created once).
fn volume(spec: &str, dir: &Path, project: &str) -> Result<String, String> {
    let (src, rest) = spec.split_once(':').ok_or(format!("bad volume {spec:?}"))?;
    let host = if src.starts_with('.') || src.starts_with('/') || src.contains('\\') {
        dir.join(src)
    } else {
        let p = Path::new("rootfs/volumes").join(format!("{project}_{src}"));
        std::fs::create_dir_all(&p).map_err(|e| e.to_string())?;
        std::fs::canonicalize(&p).map_err(|e| e.to_string())?
    };
    Ok(format!("{}:{rest}", host.display()))
}

// ---- the YAML compose files use: block maps and lists, flow lists, quoted and plain scalars ----

fn yaml(text: &str) -> Result<Value, String> {
    let lines: Vec<(usize, String)> = text.lines()
        .map(|l| strip_comment(l).trim_end().to_string())
        .filter(|l| !l.trim().is_empty() && l.trim() != "---")
        .map(|l| (l.len() - l.trim_start().len(), l.trim_start().to_string()))
        .collect();
    let mut i = 0;
    block(&lines, &mut i, 0)
}

fn strip_comment(l: &str) -> &str {
    let mut quote = None;
    for (i, c) in l.char_indices() {
        match (c, quote) {
            ('"' | '\'', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            ('#', None) if i == 0 || l[..i].ends_with(' ') => return &l[..i],
            _ => {}
        }
    }
    l
}

fn block(lines: &[(usize, String)], i: &mut usize, indent: usize) -> Result<Value, String> {
    let Some((ind, first)) = lines.get(*i) else { return Ok(Value::Null) };
    if *ind < indent {
        return Ok(Value::Null);
    }
    let ind = *ind;
    if first.starts_with("- ") || first == "-" {
        let mut out = Vec::new();
        while let Some((d, l)) = lines.get(*i) {
            if *d != ind || !(l.starts_with("- ") || l == "-") {
                break;
            }
            let item = l[1..].trim().to_string();
            *i += 1;
            if item.is_empty() {
                out.push(block(lines, i, ind + 1)?);
            } else if let Some((k, v)) = key_value(&item) {
                // "- key: value" opens a map whose other keys sit under the dash
                let mut m = Map::new();
                m.insert(k, if v.is_empty() { block(lines, i, ind + 2)? } else { flow(&v) });
                if let Value::Object(more) = block(lines, i, ind + 2)? {
                    m.extend(more);
                }
                out.push(Value::Object(m));
            } else {
                out.push(flow(&item));
            }
        }
        return Ok(Value::Array(out));
    }
    let mut m = Map::new();
    while let Some((d, l)) = lines.get(*i) {
        if *d != ind {
            if *d > ind {
                return Err(format!("unexpected indentation at {l:?}"));
            }
            break;
        }
        let (k, v) = key_value(l).ok_or(format!("expected key: value, got {l:?}"))?;
        *i += 1;
        let v = if v.is_empty() || v == "|" || v == ">" { block(lines, i, ind + 1)? } else { flow(&v) };
        m.insert(k, v);
    }
    Ok(Value::Object(m))
}

fn key_value(l: &str) -> Option<(String, String)> {
    let (k, v) = if let Some(rest) = l.strip_prefix('"') {
        let end = rest.find('"')?;
        (&rest[..end], rest[end + 1..].strip_prefix(':')?)
    } else {
        let i = l.find(": ").or_else(|| l.ends_with(':').then(|| l.len() - 1))?;
        (&l[..i], &l[i + 1..])
    };
    Some((k.trim().to_string(), v.trim().to_string()))
}

/// A value on one line: `[a, b]`, `{a: b}`, a quoted or plain scalar.
fn flow(s: &str) -> Value {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return Value::Array(split_flow(inner).iter().map(|x| flow(x)).collect());
    }
    if let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        let m = split_flow(inner).iter().filter_map(|x| key_value(x).map(|(k, v)| (k, flow(&v)))).collect();
        return Value::Object(m);
    }
    if s.len() >= 2 && (s.starts_with('"') && s.ends_with('"') || s.starts_with('\'') && s.ends_with('\'')) {
        return json!(s[1..s.len() - 1]);
    }
    json!(s)
}

fn split_flow(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth, mut quote) = (Vec::new(), String::new(), 0, None);
    for c in s.chars() {
        match (c, quote) {
            ('"' | '\'', None) => quote = Some(c),
            (q, Some(o)) if q == o => quote = None,
            ('[' | '{', None) => depth += 1,
            (']' | '}', None) => depth -= 1,
            (',', None) if depth == 0 => {
                out.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[test]
fn compose_yaml() {
    let doc = yaml("services:\n  web:  # the app\n    image: \"nginx:alpine\"\n    ports: [\"8080:80\"]\n    environment:\n      A: 1\n      B: \"two words\"\n    depends_on:\n      - db\n  db:\n    image: postgres\n    volumes:\n      - data:/var/lib/postgresql/data\n    command: postgres -c fsync=off\n").unwrap();
    let web = &doc["services"]["web"];
    assert_eq!(web["image"], "nginx:alpine");
    assert_eq!(list(&web["ports"]), ["8080:80"]);
    assert_eq!(env_list(&web["environment"]), ["A=1", "B=two words"]);
    assert_eq!(start_order(doc["services"].as_object().unwrap()).unwrap(), ["db", "web"]);
    assert_eq!(words(&doc["services"]["db"]["command"]), ["postgres", "-c", "fsync=off"]);
    assert_eq!(words(&json!("redis-server --save \"\" --x 'a b'")), ["redis-server", "--save", "", "--x", "a b"]);
    assert_eq!(list(&doc["services"]["db"]["volumes"]), ["data:/var/lib/postgresql/data"]);
}
