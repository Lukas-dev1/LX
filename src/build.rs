//! `lx build -t name[:tag] [-f Dockerfile] [--build-arg K=V] <context>`: an image from a Dockerfile, like
//! `docker build`. Each FROM starts a stage (FROM image AS name); COPY --from takes files from an earlier
//! stage or an image; the last stage is the image.
//!
//! The new image starts as a hard-link copy of its FROM image (instant, no admin rights needed; the links
//! share the :lx mode stream too). Each RUN is an `lx run` of the image so far with a writable layer that's
//! kept: its changes are then moved into the image (whiteouts delete, everything else replaces), so a file
//! the base image still links to is never written in place. COPY/ADD copy from the context; ENV, WORKDIR,
//! USER, CMD, ENTRYPOINT, SHELL and ARG update the config. The result sits where `lx run name:tag` looks.
//! ponytail: no build cache (every build starts over), ADD doesn't fetch URLs or unpack archives,
//! .dockerignore isn't read, and ARG scope isn't per stage.

use crate::fs::{enc, get_meta, set_meta, OPAQUE, WHITEOUT};
use crate::image::Ref;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// `build_args` are `--build-arg K=V`: they win over the Dockerfile's ARG defaults.
pub fn build(tag: &str, context: &Path, dockerfile: &Path, build_args: Vec<(String, String)>) -> Result<(), String> {
    let text = std::fs::read_to_string(dockerfile).map_err(|e| format!("{}: {e}", dockerfile.display()))?;
    let target = Ref::parse(tag).dir();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let work = target.with_file_name(format!(".build-{nanos}"));
    let r = run_steps(&text, context, &work, build_args.into_iter().collect());
    let r = r.and_then(|last| {
        let _ = std::fs::remove_dir_all(&target);
        std::fs::rename(&last, &target).map_err(|e| format!("{}: {e}", target.display()))?;
        Ref::parse(tag).record_name(&target);
        Ok(())
    });
    let _ = std::fs::remove_dir_all(&work); // the other stages
    if r.is_ok() {
        eprintln!("[lx] built {tag}");
    }
    r
}

/// The image directory (config.json + rootfs) a FROM or COPY --from names: an earlier stage (by
/// `AS` name or number) or an image, pulled if missing.
fn source(name: &str, stages: &[(Option<String>, PathBuf)]) -> Result<PathBuf, String> {
    let by_name = stages.iter().find(|(n, _)| n.as_deref() == Some(name));
    let by_index = name.parse::<usize>().ok().and_then(|i| stages.get(i));
    if let Some((_, dir)) = by_name.or(by_index) {
        return Ok(dir.clone());
    }
    let r = Ref::parse(name);
    if r.dir().join("config.json").exists() { Ok(r.dir()) } else { crate::image::pull(&r) }
}

/// Runs the Dockerfile; returns the last stage's directory (the image).
fn run_steps(text: &str, context: &Path, work: &Path, mut args: HashMap<String, String>) -> Result<PathBuf, String> {
    let mut stages: Vec<(Option<String>, PathBuf)> = Vec::new();
    let mut cur = work.to_path_buf(); // this stage's directory
    let mut root = cur.join("rootfs");
    let mut config = json!({});
    let mut shell = vec!["/bin/sh".to_string(), "-c".to_string()];
    for (n, (op, rest)) in instructions(text).into_iter().enumerate() {
        eprintln!("[lx] step {}: {op} {rest}", n + 1);
        let env = env_map(&config);
        // Like Docker: commands are left to the shell (which sees ENV and ARG in its environment).
        let rest = if matches!(op.as_str(), "RUN" | "CMD" | "ENTRYPOINT") { rest } else { expand(&rest, &args, &env) };
        match op.as_str() {
            "FROM" => {
                // FROM image [AS name]: a new stage, from an image or an earlier stage.
                if !stages.is_empty() {
                    std::fs::write(cur.join("config.json"), config.to_string()).map_err(|e| e.to_string())?;
                }
                let words: Vec<&str> = rest.split_whitespace().collect();
                let image = words.first().copied().unwrap_or_default();
                let name = (words.len() == 3 && words[1].eq_ignore_ascii_case("as")).then(|| words[2].to_string());
                cur = work.join(format!("stage{}", stages.len()));
                root = cur.join("rootfs");
                std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
                config = json!({});
                shell = vec!["/bin/sh".to_string(), "-c".to_string()];
                if image != "scratch" {
                    let base = source(image, &stages)?;
                    link_tree(&base.join("rootfs"), &root).map_err(|e| format!("copying {image}: {e}"))?;
                    let raw = std::fs::read(base.join("config.json")).map_err(|e| e.to_string())?;
                    config = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                }
                if config["config"].is_null() {
                    config["config"] = json!({});
                }
                stages.push((name, cur.clone()));
            }
            _ if stages.is_empty() && op != "ARG" => return Err(format!("{op} before FROM")),
            "ARG" => {
                let (k, v) = rest.split_once('=').map_or((rest.as_str(), None), |(k, v)| (k, Some(unquote(v))));
                if let Some(v) = v {
                    args.entry(k.trim().to_string()).or_insert(v);
                }
            }
            "ENV" => {
                let mut env = env;
                for (k, v) in pairs(&rest) {
                    env.retain(|(x, _)| *x != k);
                    env.push((k, v));
                }
                config["config"]["Env"] = json!(env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>());
            }
            "WORKDIR" => {
                let cur = config["config"]["WorkingDir"].as_str().filter(|w| !w.is_empty()).unwrap_or("/");
                let dir = if rest.starts_with('/') { rest.clone() } else { format!("{}/{rest}", cur.trim_end_matches('/')) };
                make_dirs(&root, &dir)?;
                config["config"]["WorkingDir"] = json!(dir);
            }
            "USER" => config["config"]["User"] = json!(rest),
            "CMD" => config["config"]["Cmd"] = json!(command(&rest, &shell)),
            "ENTRYPOINT" => config["config"]["Entrypoint"] = json!(command(&rest, &shell)),
            "SHELL" => shell = serde_json::from_str(&rest).map_err(|_| "SHELL wants a JSON array")?,
            "EXPOSE" => {
                for p in rest.split_whitespace() {
                    let p = if p.contains('/') { p.to_string() } else { format!("{p}/tcp") };
                    config["config"]["ExposedPorts"][p] = json!({});
                }
            }
            "LABEL" => {
                for (k, v) in pairs(&rest) {
                    config["config"]["Labels"][k] = json!(v);
                }
            }
            "COPY" | "ADD" => copy(&rest, context, &root, &config, &stages)?,
            "RUN" => run(&rest, &shell, &cur, &config, &args)?,
            "VOLUME" | "STOPSIGNAL" | "HEALTHCHECK" | "MAINTAINER" | "ONBUILD" => {} // nothing lx acts on yet
            _ => return Err(format!("unknown instruction {op}")),
        }
    }
    if stages.is_empty() {
        return Err("no FROM".into());
    }
    std::fs::write(cur.join("config.json"), config.to_string()).map_err(|e| e.to_string())?;
    Ok(cur)
}

/// (INSTRUCTION, arguments): comments and blank lines dropped, `\` continuations joined.
fn instructions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        let t = line.trim();
        if cur.is_empty() && (t.is_empty() || t.starts_with('#')) {
            continue;
        }
        if t.starts_with('#') {
            continue; // a comment inside a continued instruction
        }
        match t.strip_suffix('\\') {
            Some(part) => {
                cur.push_str(part);
                cur.push(' ');
            }
            None => {
                cur.push_str(t);
                let (op, rest) = cur.split_once(char::is_whitespace).unwrap_or((&cur, ""));
                out.push((op.to_ascii_uppercase(), rest.trim().to_string()));
                cur.clear();
            }
        }
    }
    out
}

/// `$VAR` and `${VAR}` from ARG values and the env so far (unknown: empty).
fn expand(s: &str, args: &HashMap<String, String>, env: &[(String, String)]) -> String {
    let get = |k: &str| env.iter().rev().find(|(x, _)| x == k).map(|(_, v)| v.clone()).or_else(|| args.get(k).cloned()).unwrap_or_default();
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let braced = it.peek() == Some(&'{');
        if braced {
            it.next();
        }
        let mut name = String::new();
        while let Some(&c) = it.peek() {
            if braced && c == '}' {
                it.next();
                break;
            }
            if !braced && !(c.is_ascii_alphanumeric() || c == '_') {
                break;
            }
            name.push(c);
            it.next();
        }
        if name.is_empty() && !braced { out.push('$') } else { out.push_str(&get(&name)) }
    }
    out
}

fn env_map(config: &Value) -> Vec<(String, String)> {
    let env = config["config"]["Env"].as_array().cloned().unwrap_or_default();
    env.iter().filter_map(|e| e.as_str()?.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect()
}

/// `K=V K2="v 2"` (or the old `K value` form).
fn pairs(s: &str) -> Vec<(String, String)> {
    if !s.contains('=') || s.split_whitespace().next().is_some_and(|w| !w.contains('=')) {
        let (k, v) = s.split_once(char::is_whitespace).unwrap_or((s, ""));
        return vec![(k.to_string(), v.trim().to_string())];
    }
    let mut out = Vec::new();
    let mut rest = s.trim();
    while let Some((k, after)) = rest.split_once('=') {
        let (v, next) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"').unwrap_or(q.len());
            (q[..end].to_string(), q.get(end + 1..).unwrap_or(""))
        } else {
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            (after[..end].to_string(), &after[end..])
        };
        out.push((k.trim().to_string(), v));
        rest = next.trim();
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// Exec form (`["a", "b"]`) or shell form (run by the SHELL).
fn command(s: &str, shell: &[String]) -> Vec<String> {
    if s.starts_with('[') && let Ok(v) = serde_json::from_str::<Vec<String>>(s) {
        return v;
    }
    shell.iter().cloned().chain([s.to_string()]).collect()
}

/// RUN: an `lx run` of the image so far, its layer kept and moved into the image.
fn run(rest: &str, shell: &[String], work: &Path, config: &Value, args: &HashMap<String, String>) -> Result<(), String> {
    std::fs::write(work.join("config.json"), config.to_string()).map_err(|e| e.to_string())?;
    let layer = work.join("layer");
    let _ = std::fs::remove_dir_all(&layer);
    let argv = command(rest, shell);
    let mut cmd = std::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.arg("run").args(["--entrypoint", "", "--layer"]).arg(&layer);
    for (k, v) in args {
        cmd.args(["-e", &format!("{k}={v}")]); // ARGs are in the environment of RUN, like Docker
    }
    cmd.arg(format!("dir:{}", work.display())).args(&argv);
    cmd.env_remove("LX_IN_JOB"); // a container of its own
    let status = cmd.status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("RUN {rest}: exit code {}", status.code().unwrap_or(-1)));
    }
    merge(&layer.join("upper"), &work.join("rootfs"), true).map_err(|e| format!("RUN {rest}: {e}"))?;
    let _ = std::fs::remove_dir_all(&layer);
    Ok(())
}

/// Move a container layer's changes into the image: whiteouts delete, an opaque directory replaces the
/// image's, everything else replaces what's there (never written in place: it may be a hard link the
/// base image shares). lx's own per-run files (/etc/resolv.conf, /etc/hosts) aren't image content.
fn merge(upper: &Path, root: &Path, top: bool) -> std::io::Result<()> {
    if upper.join(OPAQUE).exists() {
        for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
            remove(&e.path());
        }
    }
    for e in std::fs::read_dir(upper)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == OPAQUE {
            continue;
        }
        if let Some(gone) = name.strip_prefix(WHITEOUT) {
            remove(&root.join(gone));
            continue;
        }
        let (from, to) = (e.path(), root.join(&name));
        if e.file_type()?.is_dir() {
            if to.is_file() {
                remove(&to);
            }
            std::fs::create_dir_all(&to)?;
            if let Some(m) = get_meta(&from) {
                set_meta(&to, m)?;
            }
            if top && name == "etc" {
                for f in ["resolv.conf", "hosts"] {
                    let _ = std::fs::remove_file(from.join(f));
                }
            }
            merge(&from, &to, false)?;
        } else {
            remove(&to);
            std::fs::rename(&from, &to)?;
        }
    }
    Ok(())
}

fn remove(p: &Path) {
    let _ = if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
}

/// A hard-link copy of an image's files; directories are new, with the same :lx metadata.
fn link_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    if let Some(m) = get_meta(from) {
        set_meta(to, m)?;
    }
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let t = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            link_tree(&e.path(), &t)?;
        } else {
            std::fs::hard_link(e.path(), &t)?;
        }
    }
    Ok(())
}

/// The host path of a guest path in the image (no symlinks followed: ponytail).
fn host_path(root: &Path, guest: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(guest.split('/').filter(|c| !c.is_empty() && *c != ".").map(enc));
    p
}

fn make_dirs(root: &Path, guest: &str) -> Result<(), String> {
    let mut p = root.to_path_buf();
    for c in guest.split('/').filter(|c| !c.is_empty()) {
        p.push(enc(c));
        if !p.exists() {
            std::fs::create_dir(&p).map_err(|e| format!("{guest}: {e}"))?;
            let _ = set_meta(&p, [0o755, 0, 0]);
        }
    }
    Ok(())
}

/// COPY/ADD [--chown=u[:g]] [--from=stage|image] <src>... <dest>: from the build context (or, with
/// --from, absolute paths in an earlier stage or an image), relative to WORKDIR.
fn copy(rest: &str, context: &Path, root: &Path, config: &Value, stages: &[(Option<String>, PathBuf)]) -> Result<(), String> {
    let mut words: Vec<String> = if rest.starts_with('[') {
        serde_json::from_str(rest).map_err(|_| "bad COPY array")?
    } else {
        rest.split_whitespace().map(String::from).collect()
    };
    let (mut owner, mut from_root) = (None, None);
    while words.first().is_some_and(|w| w.starts_with("--")) {
        let flag = words.remove(0);
        if let Some(spec) = flag.strip_prefix("--chown=") {
            let (u, g, _) = crate::image::resolve_user(root, spec)?;
            owner = Some((u, g));
        } else if let Some(name) = flag.strip_prefix("--from=") {
            from_root = Some(source(name, stages)?.join("rootfs"));
        }
    }
    let dest = words.pop().ok_or("COPY needs a destination")?;
    let cwd = config["config"]["WorkingDir"].as_str().filter(|w| !w.is_empty()).unwrap_or("/");
    let dest = if dest.starts_with('/') { dest } else { format!("{}/{dest}", cwd.trim_end_matches('/')) };
    let into_dir = dest.ends_with('/') || words.len() > 1;
    for src in &words {
        let from = match &from_root {
            Some(r) => host_path(r, src), // ponytail: symlinks on the way aren't followed
            None => {
                let from = std::fs::canonicalize(context.join(src)).map_err(|e| format!("COPY {src}: {e}"))?;
                let ctx = std::fs::canonicalize(context).map_err(|e| e.to_string())?;
                if !from.starts_with(&ctx) {
                    return Err(format!("COPY {src}: outside the build context"));
                }
                from
            }
        };
        if !from.exists() {
            return Err(format!("COPY {src}: not found"));
        }
        let to_guest = if from.is_dir() || !(into_dir || host_path(root, &dest).is_dir()) {
            dest.clone()
        } else {
            let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or(src);
            format!("{}/{name}", dest.trim_end_matches('/'))
        };
        let parent = to_guest.rsplit_once('/').map_or("/", |(p, _)| if p.is_empty() { "/" } else { p });
        make_dirs(root, parent)?;
        copy_in(&from, &host_path(root, &to_guest), owner, from_root.is_some()).map_err(|e| format!("COPY {src}: {e}"))?;
    }
    Ok(())
}

/// Copy a file or tree into the image, replacing (never writing through: hard links) what's there.
/// From the context: files 0644 (0755 if it starts like a script or an ELF), directories 0755, root's
/// unless `owner`. From an image (`imaged`): names are already host-encoded, modes and owners kept.
fn copy_in(from: &Path, to: &Path, owner: Option<(u32, u32)>, imaged: bool) -> std::io::Result<()> {
    let meta = |default: u32| {
        let kept = if imaged { get_meta(from) } else { None };
        let [mode, uid, gid] = kept.unwrap_or([default, 0, 0]);
        let (uid, gid) = owner.unwrap_or((uid, gid));
        [mode, uid, gid]
    };
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        set_meta(to, meta(0o755))?;
        for e in std::fs::read_dir(from)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            copy_in(&e.path(), &to.join(if imaged { name } else { enc(&name) }), owner, imaged)?;
        }
        return Ok(());
    }
    remove(to);
    std::fs::copy(from, to)?;
    let mut head = [0u8; 4];
    let n = std::io::Read::read(&mut std::fs::File::open(from)?, &mut head)?;
    let exec = head[..n].starts_with(b"#!") || head[..n].starts_with(b"\x7fELF");
    set_meta(to, meta(if exec { 0o755 } else { 0o644 }))
}
