//! `lx build -t name[:tag] [-f Dockerfile] [--build-arg K=V] <context>`: an image from a Dockerfile, like
//! `docker build`. Each FROM starts a stage (FROM image AS name); COPY --from takes files from an earlier
//! stage or an image; the last stage is the image.
//!
//! The new image starts as a hard-link copy of its FROM image (instant, no admin rights needed; the links
//! share the :lx mode stream too). Each RUN is an `lx run` of the image so far with a writable layer that's
//! kept: its changes are then moved into the image (whiteouts delete, everything else replaces), so a file
//! the base image still links to is never written in place. COPY/ADD copy from the context; ENV, WORKDIR,
//! USER, CMD, ENTRYPOINT, SHELL and ARG update the config. The result sits where `lx run name:tag` looks.
//! RUN layers are cached (see "build cache" below) and .dockerignore is honoured.
//! ADD unpacks local .tar/.tar.gz/.tgz archives. ponytail: ADD doesn't fetch URLs, and ARG scope isn't
//! per stage.

use crate::fs::{enc, get_meta, set_meta, OPAQUE, WHITEOUT};
use crate::image::Ref;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// `build_args` are `--build-arg K=V`: they win over the Dockerfile's ARG defaults. `no_cache`: run every
/// RUN again (`--no-cache`).
pub fn build(tag: &str, context: &Path, dockerfile: &Path, build_args: Vec<(String, String)>, no_cache: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(dockerfile).map_err(|e| format!("{}: {e}", dockerfile.display()))?;
    let target = Ref::parse(tag).dir();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let work = target.with_file_name(format!(".build-{nanos}"));
    let r = run_steps(&text, context, &work, build_args.into_iter().collect(), no_cache);
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

// ---- build cache ----
//
// Every instruction extends a key: a hash of the stage's key so far, the instruction, and what it reads
// (for FROM the base's config, for COPY the sources' paths, sizes and mtimes, for RUN the ARG values).
// A RUN's layer is kept in rootfs/buildcache/<key> and hard-linked into the image; the same key later
// links it again instead of running. ponytail: never pruned (delete rootfs/buildcache to reclaim space).

const CACHE: &str = "rootfs/buildcache";

fn mix(key: u64, parts: &[&[u8]]) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new(); // fixed keys: the same input hashes the same in every build
    key.hash(&mut h);
    parts.hash(&mut h);
    h.finish()
}

/// A COPY source's paths, sizes and mtimes (what docker's checksum stands for, without reading contents).
fn fingerprint(p: &Path, ignore: &Ignore, mut key: u64) -> u64 {
    let Ok(m) = std::fs::metadata(p) else { return key };
    let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).unwrap_or_default();
    key = mix(key, &[p.to_string_lossy().as_bytes(), &m.len().to_le_bytes(), &t.as_nanos().to_le_bytes()]);
    if m.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(p).into_iter().flatten().flatten().map(|e| e.path()).collect();
        entries.sort();
        for e in entries.iter().filter(|e| !ignore.skips(e)) {
            key = fingerprint(e, ignore, key);
        }
    }
    key
}

/// Runs the Dockerfile; returns the last stage's directory (the image).
fn run_steps(text: &str, context: &Path, work: &Path, mut args: HashMap<String, String>, no_cache: bool) -> Result<PathBuf, String> {
    let mut stages: Vec<(Option<String>, PathBuf)> = Vec::new();
    let mut stage_keys: Vec<u64> = Vec::new();
    let mut key = 0u64;
    let mut cur = work.to_path_buf(); // this stage's directory
    let mut root = cur.join("rootfs");
    let mut config = json!({});
    let mut shell = vec!["/bin/sh".to_string(), "-c".to_string()];
    let ignore = Ignore::load(context);
    for (n, (op, rest)) in instructions(text).into_iter().enumerate() {
        eprintln!("[lx] step {}: {op} {rest}", n + 1);
        let env = env_map(&config);
        // Like Docker: commands are left to the shell (which sees ENV and ARG in its environment).
        let rest = if matches!(op.as_str(), "RUN" | "CMD" | "ENTRYPOINT") { rest } else { expand(&rest, &args, &env) };
        key = mix(key, &[op.as_bytes(), rest.as_bytes()]);
        match op.as_str() {
            "FROM" => {
                let image = rest.split_whitespace().next().unwrap_or_default();
                key = match stages.iter().position(|(n, _)| n.as_deref() == Some(image)) {
                    Some(i) => mix(0, &[&stage_keys[i].to_le_bytes()]),
                    None => mix(0, &[image.as_bytes(), &source(image, &[]).ok().and_then(|d| std::fs::read(d.join("config.json")).ok()).unwrap_or_default()]),
                };
            }
            "COPY" | "ADD" => {
                for w in rest.split_whitespace() {
                    if let Some(s) = w.strip_prefix("--from=") {
                        let k = stages.iter().position(|(n, _)| n.as_deref() == Some(s)).map(|i| stage_keys[i]);
                        key = mix(key, &[&k.unwrap_or_default().to_le_bytes()]);
                    } else if !w.starts_with("--") {
                        key = fingerprint(&context.join(w), &ignore, key);
                    }
                }
            }
            "RUN" => {
                let mut a: Vec<String> = args.iter().map(|(k, v)| format!("{k}={v}")).collect();
                a.sort();
                key = mix(key, &[a.join("\n").as_bytes()]);
            }
            _ => {}
        }
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
                // Every marker this build makes carries the attribute; the base's did if it's stamped.
                if image == "scratch" || source(image, &stages)?.join(crate::fs::MARKED).exists() {
                    std::fs::write(cur.join(crate::fs::MARKED), b"").map_err(|e| e.to_string())?;
                }
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
                stage_keys.push(key);
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
            "COPY" | "ADD" => copy(&rest, op == "ADD", context, &root, &config, &stages, &ignore)?,
            "RUN" => run(&rest, &shell, &cur, &config, &args, key, no_cache)?,
            "VOLUME" | "STOPSIGNAL" | "HEALTHCHECK" | "MAINTAINER" | "ONBUILD" => {} // nothing lx acts on yet
            _ => return Err(format!("unknown instruction {op}")),
        }
        if let Some(k) = stage_keys.last_mut() {
            *k = key; // COPY --from and FROM <stage> see the stage as far as it got
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

/// RUN: an `lx run` of the image so far; its layer goes into the build cache under `key` and is linked
/// into the image from there. With that key already cached, only the linking happens.
fn run(rest: &str, shell: &[String], work: &Path, config: &Value, args: &HashMap<String, String>, key: u64, no_cache: bool) -> Result<(), String> {
    let cached = Path::new(CACHE).join(format!("{key:016x}"));
    if !no_cache && cached.join("upper").is_dir() {
        eprintln!("[lx]   (cached)");
        return merge(&cached.join("upper"), &work.join("rootfs")).map_err(|e| format!("RUN {rest}: {e}"));
    }
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
    // Into the cache (lx's per-run /etc files aren't image content), then linked into the image.
    for f in ["resolv.conf", "hosts"] {
        let _ = std::fs::remove_file(layer.join("upper").join("etc").join(f));
    }
    let _ = std::fs::remove_dir_all(&cached);
    std::fs::create_dir_all(&cached).map_err(|e| e.to_string())?;
    std::fs::rename(layer.join("upper"), cached.join("upper")).map_err(|e| format!("RUN {rest}: caching its layer: {e}"))?;
    let _ = std::fs::remove_dir_all(&layer);
    merge(&cached.join("upper"), &work.join("rootfs")).map_err(|e| format!("RUN {rest}: {e}"))
}

/// Apply a cached RUN layer to the image: whiteouts delete, an opaque directory replaces the image's,
/// files are hard-linked in, replacing what's there (never written in place: it may be a hard link the
/// base image or the cache shares).
fn merge(upper: &Path, root: &Path) -> std::io::Result<()> {
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
            merge(&from, &to)?;
        } else {
            remove(&to);
            std::fs::hard_link(&from, &to)?;
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
fn copy(rest: &str, add: bool, context: &Path, root: &Path, config: &Value, stages: &[(Option<String>, PathBuf)], ignore: &Ignore) -> Result<(), String> {
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
        // ADD of a local tar archive (plain or gzip) unpacks it into the destination directory.
        let archive = [".tar", ".tar.gz", ".tgz"].iter().any(|x| src.ends_with(x));
        if add && from_root.is_none() && from.is_file() && archive {
            make_dirs(root, &dest)?;
            crate::fs::unpack(&from, &host_path(root, &dest)).map_err(|e| format!("ADD {src}: {e}"))?;
            continue;
        }
        let to_guest = if from.is_dir() || !(into_dir || host_path(root, &dest).is_dir()) {
            dest.clone()
        } else {
            let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or(src);
            format!("{}/{name}", dest.trim_end_matches('/'))
        };
        let parent = to_guest.rsplit_once('/').map_or("/", |(p, _)| if p.is_empty() { "/" } else { p });
        make_dirs(root, parent)?;
        copy_in(&from, &host_path(root, &to_guest), owner, from_root.is_some(), ignore).map_err(|e| format!("COPY {src}: {e}"))?;
    }
    Ok(())
}

/// `.dockerignore`: patterns (`*`, `?`, `**`, a leading `!` re-includes) on paths relative to the context;
/// the last pattern that matches decides. An ignored directory is skipped whole.
/// ponytail: a `!` exception inside an ignored directory isn't reached.
pub struct Ignore {
    ctx: PathBuf,
    rules: Vec<(bool, Vec<String>)>, // (re-include, pattern segments)
}

impl Ignore {
    fn load(context: &Path) -> Ignore {
        let text = std::fs::read_to_string(context.join(".dockerignore")).unwrap_or_default();
        let rules = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(|l| {
            let (neg, p) = l.strip_prefix('!').map_or((false, l), |p| (true, p));
            (neg, p.trim_start_matches("./").trim_matches('/').split('/').map(String::from).collect())
        }).collect();
        Ignore { ctx: std::fs::canonicalize(context).unwrap_or(context.to_path_buf()), rules }
    }

    fn skips(&self, host: &Path) -> bool {
        let Ok(rel) = host.strip_prefix(&self.ctx) else { return false };
        let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        let mut skip = false;
        for (neg, pat) in &self.rules {
            if path_matches(pat, &parts) {
                skip = !neg;
            }
        }
        skip
    }
}

fn path_matches(pat: &[String], parts: &[String]) -> bool {
    match (pat.first(), parts.first()) {
        (None, None) => true,
        (Some(p), _) if p == "**" => path_matches(&pat[1..], parts) || (!parts.is_empty() && path_matches(pat, &parts[1..])),
        (Some(p), Some(s)) => glob(p.as_bytes(), s.as_bytes()) && path_matches(&pat[1..], &parts[1..]),
        _ => false,
    }
}

fn glob(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
        _ => false,
    }
}

#[test]
fn dockerignore_patterns() {
    let m = |p: &str, s: &str| path_matches(&p.split('/').map(String::from).collect::<Vec<_>>(), &s.split('/').map(String::from).collect::<Vec<_>>());
    assert!(m("node_modules", "node_modules"));
    assert!(!m("node_modules", "src/node_modules"));
    assert!(m("**/node_modules", "src/node_modules"));
    assert!(m("*.log", "debug.log") && !m("*.log", "logs/debug.log"));
    assert!(m("**/*.log", "logs/debug.log") && m("**/*.log", "debug.log"));
    assert!(m("src/?.rs", "src/a.rs") && !m("src/?.rs", "src/ab.rs"));
}

/// Copy a file or tree into the image, replacing (never writing through: hard links) what's there.
/// From the context: files 0644 (0755 if it starts like a script or an ELF), directories 0755, root's
/// unless `owner`. From an image (`imaged`): names are already host-encoded, modes and owners kept.
fn copy_in(from: &Path, to: &Path, owner: Option<(u32, u32)>, imaged: bool, ignore: &Ignore) -> std::io::Result<()> {
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
            if !imaged && ignore.skips(&e.path()) {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            copy_in(&e.path(), &to.join(if imaged { name } else { enc(&name) }), owner, imaged, ignore)?;
        }
        return Ok(());
    }
    remove(to);
    std::fs::copy(from, to)?;
    if imaged {
        crate::fs::mark_if_marker(to); // COPY --from an image made before marker attributes
    }
    let mut head = [0u8; 4];
    let n = std::io::Read::read(&mut std::fs::File::open(from)?, &mut head)?;
    let exec = head[..n].starts_with(b"#!") || head[..n].starts_with(b"\x7fELF");
    set_meta(to, meta(if exec { 0o755 } else { 0o644 }))
}
