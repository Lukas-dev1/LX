//! `lx build -t name[:tag] [-f Dockerfile] <context>`: an image from a Dockerfile, like `docker build`.
//!
//! The new image starts as a hard-link copy of its FROM image (instant, no admin rights needed; the links
//! share the :lx mode stream too). Each RUN is an `lx run` of the image so far with a writable layer that's
//! kept: its changes are then moved into the image (whiteouts delete, everything else replaces), so a file
//! the base image still links to is never written in place. COPY/ADD copy from the context; ENV, WORKDIR,
//! USER, CMD, ENTRYPOINT, SHELL and ARG update the config. The result sits where `lx run name:tag` looks.
//! ponytail: one stage (no `FROM ... AS` + `COPY --from`), no build cache, ADD doesn't fetch URLs or
//! unpack archives, and .dockerignore isn't read.

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
    if r.is_ok() {
        let _ = std::fs::remove_dir_all(&target);
        std::fs::rename(&work, &target).map_err(|e| format!("{}: {e}", target.display()))?;
        eprintln!("[lx] built {tag}");
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }
    r
}

fn run_steps(text: &str, context: &Path, work: &Path, mut args: HashMap<String, String>) -> Result<(), String> {
    let root = work.join("rootfs");
    let mut config = json!({});
    let mut shell = vec!["/bin/sh".to_string(), "-c".to_string()];
    let mut from = false;
    for (n, (op, rest)) in instructions(text).into_iter().enumerate() {
        eprintln!("[lx] step {}: {op} {rest}", n + 1);
        let env = env_map(&config);
        // Like Docker: commands are left to the shell (which sees ENV and ARG in its environment).
        let rest = if matches!(op.as_str(), "RUN" | "CMD" | "ENTRYPOINT") { rest } else { expand(&rest, &args, &env) };
        match op.as_str() {
            "FROM" if from => return Err("multi-stage builds (a second FROM) aren't supported yet".into()),
            "FROM" => {
                from = true;
                let image = rest.split_whitespace().next().unwrap_or_default();
                std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
                if image != "scratch" {
                    let r = Ref::parse(image);
                    let base = if r.dir().join("config.json").exists() { r.dir() } else { crate::image::pull(&r)? };
                    link_tree(&base.join("rootfs"), &root).map_err(|e| format!("copying {image}: {e}"))?;
                    let raw = std::fs::read(base.join("config.json")).map_err(|e| e.to_string())?;
                    config = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                }
                if config["config"].is_null() {
                    config["config"] = json!({});
                }
            }
            _ if !from && op != "ARG" => return Err(format!("{op} before FROM")),
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
            "COPY" | "ADD" => copy(&rest, context, &root, &config)?,
            "RUN" => run(&rest, &shell, work, &config, &args)?,
            "VOLUME" | "STOPSIGNAL" | "HEALTHCHECK" | "MAINTAINER" | "ONBUILD" => {} // nothing lx acts on yet
            _ => return Err(format!("unknown instruction {op}")),
        }
    }
    if !from {
        return Err("no FROM".into());
    }
    std::fs::write(work.join("config.json"), config.to_string()).map_err(|e| e.to_string())
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

/// COPY/ADD [--chown=u[:g]] <src>... <dest>: from the build context, relative to WORKDIR.
fn copy(rest: &str, context: &Path, root: &Path, config: &Value) -> Result<(), String> {
    let mut words: Vec<String> = if rest.starts_with('[') {
        serde_json::from_str(rest).map_err(|_| "bad COPY array")?
    } else {
        rest.split_whitespace().map(String::from).collect()
    };
    let mut owner = (0, 0);
    while words.first().is_some_and(|w| w.starts_with("--")) {
        let flag = words.remove(0);
        if let Some(spec) = flag.strip_prefix("--chown=") {
            let (u, g, _) = crate::image::resolve_user(root, spec)?;
            owner = (u, g);
        } else if flag.starts_with("--from") {
            return Err("COPY --from (multi-stage) isn't supported yet".into());
        }
    }
    let dest = words.pop().ok_or("COPY needs a destination")?;
    let cwd = config["config"]["WorkingDir"].as_str().filter(|w| !w.is_empty()).unwrap_or("/");
    let dest = if dest.starts_with('/') { dest } else { format!("{}/{dest}", cwd.trim_end_matches('/')) };
    let into_dir = dest.ends_with('/') || words.len() > 1;
    for src in &words {
        let from = context.join(src);
        let from = std::fs::canonicalize(&from).map_err(|e| format!("COPY {src}: {e}"))?;
        let ctx = std::fs::canonicalize(context).map_err(|e| e.to_string())?;
        if !from.starts_with(&ctx) {
            return Err(format!("COPY {src}: outside the build context"));
        }
        let to_guest = if from.is_dir() || !(into_dir || host_path(root, &dest).is_dir()) {
            dest.clone()
        } else {
            format!("{}/{}", dest.trim_end_matches('/'), from.file_name().unwrap_or_default().to_string_lossy())
        };
        let parent = to_guest.rsplit_once('/').map_or("/", |(p, _)| if p.is_empty() { "/" } else { p });
        make_dirs(root, parent)?;
        copy_in(&from, &host_path(root, &to_guest), owner).map_err(|e| format!("COPY {src}: {e}"))?;
    }
    Ok(())
}

/// Copy a host file or tree into the image: files 0644 (0755 if it starts like a script or an ELF),
/// directories 0755, owned by `owner`. Existing files are replaced, not written through (hard links).
fn copy_in(from: &Path, to: &Path, owner: (u32, u32)) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        set_meta(to, [0o755, owner.0, owner.1])?;
        for e in std::fs::read_dir(from)? {
            let e = e?;
            copy_in(&e.path(), &to.join(enc(&e.file_name().to_string_lossy())), owner)?;
        }
        return Ok(());
    }
    remove(to);
    std::fs::copy(from, to)?;
    let mut head = [0u8; 4];
    let n = std::io::Read::read(&mut std::fs::File::open(from)?, &mut head)?;
    let exec = head[..n].starts_with(b"#!") || head[..n].starts_with(b"\x7fELF");
    set_meta(to, [if exec { 0o755 } else { 0o644 }, owner.0, owner.1])
}
