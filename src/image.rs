//! Pull images from an OCI/Docker registry (Docker Hub by default) and read their run config.
//! HTTPS goes through Windows' own curl.exe (System32, since Windows 10 1803), so lx carries no TLS
//! stack. Blobs are verified against their sha256 digests with BCrypt before anything is unpacked.
use crate::fs;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where pulled images live. Under rootfs/ with the other untrusted guest data.
const STORE: &str = "rootfs/images";

pub struct Ref {
    registry: String,
    repo: String,
    tag: String, // a tag, or "sha256:..." for a digest reference
}

impl Ref {
    /// `nginx`, `nginx:alpine`, `user/app:1`, `ghcr.io/org/app:tag`, `alpine@sha256:...`
    pub fn parse(s: &str) -> Ref {
        let (name, tag) = match s.split_once('@') {
            Some((n, d)) => (n, d.to_string()),
            None => match s.rsplit_once(':').filter(|(_, t)| !t.contains('/')) {
                Some((n, t)) => (n, t.to_string()),
                None => (s, "latest".to_string()),
            },
        };
        let (registry, repo) = match name.split_once('/') {
            Some((host, rest)) if host.contains(['.', ':']) || host == "localhost" => (host.to_string(), rest.to_string()),
            _ if name.contains('/') => ("registry-1.docker.io".to_string(), name.to_string()),
            _ => ("registry-1.docker.io".to_string(), format!("library/{name}")),
        };
        Ref { registry, repo, tag }
    }

    /// Local directory for this image. Names are sanitized: they come from the command line and
    /// end up as path components.
    pub fn dir(&self) -> PathBuf {
        let safe = |s: &str| {
            let s: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
            if s.chars().all(|c| c == '.') { "_".repeat(s.len().max(1)) } else { s } // never "." or ".."
        };
        Path::new(STORE).join(safe(&self.registry)).join(safe(&self.repo)).join(safe(&self.tag))
    }

    /// As people write it: `nginx`, `user/app`, `ghcr.io/org/app`; and the tag.
    fn name(&self) -> (String, String) {
        let repo = match self.registry.as_str() {
            "registry-1.docker.io" => self.repo.strip_prefix("library/").unwrap_or(&self.repo).to_string(),
            reg => format!("{reg}/{}", self.repo),
        };
        (repo, self.tag.clone())
    }

    /// Keep the name beside the image (`dir()` can't be read back: `/` and `_` both become `_`).
    pub fn record_name(&self, dir: &Path) {
        let (repo, tag) = self.name();
        let _ = std::fs::write(dir.join("name"), format!("{repo}:{tag}"));
    }
}

/// Every image in the store: (repository, tag), from the recorded name, else a best guess from the
/// directory (images pulled before names were kept).
pub fn list() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dirs = |p: &Path| std::fs::read_dir(p).into_iter().flatten().flatten().filter(|e| e.path().is_dir()).map(|e| e.path()).collect::<Vec<_>>();
    for reg in dirs(Path::new(STORE)) {
        for repo in dirs(&reg) {
            for tag in dirs(&repo) {
                if !tag.join("config.json").exists() {
                    continue;
                }
                let file = |p: &Path| p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                let guess = || {
                    let r = file(&repo);
                    let r = r.strip_prefix("library_").map(String::from).unwrap_or(r);
                    format!("{}:{}", if file(&reg) == "registry-1.docker.io" { r } else { format!("{}/{r}", file(&reg)) }, file(&tag))
                };
                let name = std::fs::read_to_string(tag.join("name")).unwrap_or_else(|_| guess());
                let (r, t) = name.rsplit_once(':').map(|(r, t)| (r.to_string(), t.to_string())).unwrap_or((name.clone(), String::new()));
                out.push((r, t));
            }
        }
    }
    out.sort();
    out
}

struct Registry {
    base: String,
    token: Option<String>,
    tmp: PathBuf,
}

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

impl Registry {
    /// GET with the registry's token dance: on 401, read WWW-Authenticate, fetch a bearer token, retry.
    /// The body goes to `out` (for blobs) or is returned.
    fn get(&mut self, path: &str, accept: &str, out: Option<&Path>) -> Result<Vec<u8>, String> {
        let url = format!("{}{path}", self.base);
        for _ in 0..2 {
            let (code, body, headers) = curl(&url, accept, self.token.as_deref(), out, &self.tmp)?;
            if code == 401 && self.token.is_none() {
                self.token = Some(fetch_token(&headers, &self.tmp)?);
                continue;
            }
            if code != 200 {
                return Err(format!("{url}: HTTP {code} {}", String::from_utf8_lossy(&body).chars().take(200).collect::<String>()));
            }
            return Ok(body);
        }
        Err(format!("{url}: still unauthorized after getting a token"))
    }

    fn json(&mut self, path: &str, accept: &str) -> Result<Value, String> {
        serde_json::from_slice(&self.get(path, accept, None)?).map_err(|e| format!("{path}: bad JSON: {e}"))
    }
}

/// curl.exe from System32 (not whatever `curl` is on PATH). Returns (status, body, response headers).
/// curl drops the Authorization header when a blob redirect leaves the registry host.
fn curl(url: &str, accept: &str, token: Option<&str>, out: Option<&Path>, tmp: &Path) -> Result<(u16, Vec<u8>, String), String> {
    let hdr_file = tmp.join("headers.txt");
    let body_file = out.map(Path::to_path_buf).unwrap_or_else(|| tmp.join("body"));
    let mut cmd = Command::new(r"C:\Windows\System32\curl.exe");
    cmd.args(["-sS", "-L", "--max-redirs", "5", "--proto", "=https", "-w", "%{http_code}", "-H"])
        .arg(format!("Accept: {accept}"))
        .arg("-D").arg(&hdr_file)
        .arg("-o").arg(&body_file);
    if let Some(t) = token {
        cmd.arg("-H").arg(format!("Authorization: Bearer {t}"));
    }
    let o = cmd.arg(url).output().map_err(|e| format!("running curl.exe: {e}"))?;
    if !o.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    let code = String::from_utf8_lossy(&o.stdout).trim().parse().unwrap_or(0);
    let headers = std::fs::read_to_string(&hdr_file).unwrap_or_default();
    let body = if out.is_some() { Vec::new() } else { std::fs::read(&body_file).unwrap_or_default() };
    Ok((code, body, headers))
}

/// `WWW-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="..."`
fn fetch_token(headers: &str, tmp: &Path) -> Result<String, String> {
    let line = headers.lines().rev()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .ok_or("registry wants auth but sent no WWW-Authenticate")?;
    let param = |k: &str| {
        let i = line.find(&format!("{k}=\""))? + k.len() + 2;
        line[i..].split('"').next().map(String::from)
    };
    let realm = param("realm").ok_or("no realm in WWW-Authenticate")?;
    let mut url = format!("{realm}?");
    for k in ["service", "scope"] {
        if let Some(v) = param(k) {
            url += &format!("{k}={}&", v.replace(':', "%3A").replace('/', "%2F"));
        }
    }
    // ponytail: anonymous tokens only (public images). Private registries need credentials here.
    let (code, body, _) = curl(&url, "application/json", None, None, tmp)?;
    let v: Value = serde_json::from_slice(&body).map_err(|e| format!("token: {e}"))?;
    let tok = v["token"].as_str().or(v["access_token"].as_str());
    tok.map(String::from).ok_or_else(|| format!("token endpoint answered HTTP {code} without a token"))
}

/// sha256 of a file via BCrypt (Windows CNG), as lowercase hex.
fn sha256_file(p: &Path) -> Result<String, String> {
    use crate::win::*;
    use std::io::Read;
    const BCRYPT_SHA256_ALG_HANDLE: isize = 0x41;
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut h = 0isize;
    unsafe { BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut h, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, 0) };
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        unsafe { BCryptHashData(h, buf.as_ptr(), n as u32, 0) };
    }
    let mut out = [0u8; 32];
    unsafe {
        BCryptFinishHash(h, out.as_mut_ptr(), 32, 0);
        BCryptDestroyHash(h);
    }
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
}

/// Pull `r` into its store directory: `rootfs/` (all layers applied) and `config.json`.
pub fn pull(r: &Ref) -> Result<PathBuf, String> {
    let dir = r.dir();
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let mut reg = Registry { base: format!("https://{}/v2/{}", r.registry, r.repo), token: None, tmp: tmp.clone() };

    let mut m = reg.json(&format!("/manifests/{}", r.tag), MANIFEST_TYPES)?;
    if let Some(list) = m["manifests"].as_array() {
        // Multi-arch index: lx runs x86-64 Linux code natively, so pick linux/amd64.
        let pick = list.iter()
            .find(|e| e["platform"]["os"] == "linux" && e["platform"]["architecture"] == "amd64")
            .ok_or("image has no linux/amd64 variant (lx runs x86-64 code natively)")?;
        let digest = pick["digest"].as_str().ok_or("index entry without digest")?.to_string();
        m = reg.json(&format!("/manifests/{digest}"), MANIFEST_TYPES)?;
    }
    let config_digest = m["config"]["digest"].as_str().ok_or("manifest without config")?.to_string();
    let layers: Vec<(String, String)> = m["layers"].as_array().ok_or("manifest without layers")?.iter()
        .map(|l| (l["digest"].as_str().unwrap_or_default().to_string(), l["mediaType"].as_str().unwrap_or_default().to_string()))
        .collect();

    let fetch_blob = |reg: &mut Registry, digest: &str| -> Result<PathBuf, String> {
        let hex = digest.strip_prefix("sha256:").filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("unsupported digest {digest}"))?;
        let file = tmp.join(hex);
        reg.get(&format!("/blobs/{digest}"), "*/*", Some(&file))?;
        let got = sha256_file(&file)?;
        if got != hex {
            let _ = std::fs::remove_file(&file);
            return Err(format!("blob {digest}: sha256 mismatch (got {got}), refusing to use it"));
        }
        Ok(file)
    };

    let config = fetch_blob(&mut reg, &config_digest)?;
    let rootfs = dir.join("rootfs");
    let _ = std::fs::remove_dir_all(&rootfs); // a re-pull starts clean
    for (i, (digest, media)) in layers.iter().enumerate() {
        eprintln!("[lx] layer {}/{}: {}", i + 1, layers.len(), &digest[..19.min(digest.len())]);
        let blob = fetch_blob(&mut reg, digest)?;
        let plain = if media.contains("zstd") { zstd_to_tar(&blob)? } else { blob.clone() };
        fs::unpack(&plain, &rootfs)?;
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(blob);
    }
    std::fs::rename(&config, dir.join("config.json")).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&tmp);
    r.record_name(&dir);
    Ok(dir)
}

/// The parts of an image config `docker run` uses.
pub struct RunConfig {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    /// The image's USER: "name", "uid", "name:group" or "uid:gid"; empty = root.
    pub user: String,
}

/// Resolve a USER spec against the image's /etc/passwd and /etc/group: (uid, gid, home), like Docker
/// (a bare uid not in passwd is fine; its gid is then 0 and HOME is /).
pub fn resolve_user(rootfs: &Path, spec: &str) -> Result<(u32, u32, String), String> {
    let read = |f: &str| std::fs::read_to_string(rootfs.join(f)).unwrap_or_default();
    let (passwd, group) = (read("etc/passwd"), read("etc/group"));
    let spec = if spec.is_empty() { "0" } else { spec };
    let (u, g) = spec.split_once(':').map_or((spec, None), |(u, g)| (u, Some(g)));
    let entry = passwd.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f| f.len() >= 6 && (f[0] == u || f[2] == u));
    let (uid, mut gid, home) = match (&entry, u.parse::<u32>()) {
        (Some(f), _) => (f[2].parse().unwrap_or(0), f[3].parse().unwrap_or(0), f[5].to_string()),
        (None, Ok(uid)) => (uid, 0, "/".to_string()),
        (None, Err(_)) => return Err(format!("unable to find user {u}: no matching entries in passwd file")),
    };
    if let Some(g) = g {
        gid = match g.parse() {
            Ok(n) => n,
            Err(_) => group.lines().map(|l| l.split(':').collect::<Vec<_>>()).find(|f| f.len() >= 3 && f[0] == g)
                .and_then(|f| f[2].parse().ok()).ok_or(format!("unable to find group {g}"))?,
        };
    }
    Ok((uid, gid, home))
}

/// Entrypoint + (user command, else image Cmd), like `docker run`; `entrypoint` is `--entrypoint` (empty: none).
pub fn run_config(dir: &Path, cmd: &[String], entrypoint: Option<&str>) -> Result<RunConfig, String> {
    let raw = std::fs::read(dir.join("config.json")).map_err(|e| format!("{}: {e}", dir.display()))?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("config.json: {e}"))?;
    let c = &v["config"];
    let strings = |x: &Value| -> Vec<String> { x.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect() };
    let mut argv = match entrypoint {
        Some(e) => e.split_whitespace().map(String::from).collect(),
        None => strings(&c["Entrypoint"]),
    };
    argv.extend(if cmd.is_empty() { strings(&c["Cmd"]) } else { cmd.to_vec() });
    if argv.is_empty() {
        return Err("image has no Entrypoint or Cmd; give a command".into());
    }
    let mut env = strings(&c["Env"]);
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    env.push("HOSTNAME=lx".into());
    let workdir = c["WorkingDir"].as_str().filter(|w| !w.is_empty()).unwrap_or("/").to_string();
    let user = c["User"].as_str().unwrap_or("").to_string();
    Ok(RunConfig { argv, env, workdir, user })
}

#[test]
fn refs() {
    let r = Ref::parse("nginx:alpine");
    assert_eq!((r.registry.as_str(), r.repo.as_str(), r.tag.as_str()), ("registry-1.docker.io", "library/nginx", "alpine"));
    let r = Ref::parse("ghcr.io/org/app");
    assert_eq!((r.registry.as_str(), r.repo.as_str(), r.tag.as_str()), ("ghcr.io", "org/app", "latest"));
    let r = Ref::parse("localhost:5000/app:1");
    assert_eq!((r.registry.as_str(), r.repo.as_str(), r.tag.as_str()), ("localhost:5000", "app", "1"));
    assert!(Ref::parse("../../x:..").dir().starts_with(STORE));
    assert!(!Ref::parse("../../x:..").dir().components().any(|c| c == std::path::Component::ParentDir));
}

/// A zstd layer as a plain tar beside it: Windows' own tar.exe (libarchive, with libzstd since
/// Windows 10 1803's successors) re-archives it without extracting anything, and fs::unpack does the
/// rest (whiteouts, modes, NTFS name encoding) as for gzip layers.
fn zstd_to_tar(blob: &Path) -> Result<PathBuf, String> {
    let out = blob.with_extension("tar");
    let o = Command::new(r"C:\Windows\System32\tar.exe")
        .arg("-c").arg("-f").arg(&out).arg(format!("@{}", blob.display()))
        .output().map_err(|e| format!("running tar.exe: {e}"))?;
    if !o.status.success() {
        let _ = std::fs::remove_file(&out);
        return Err(format!("decompressing a zstd layer: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(out)
}

#[test]
fn zstd_layer_unpacks() {
    let base = std::env::temp_dir().join(format!("lx-zstd-{}", std::process::id()));
    let src = base.join("src");
    std::fs::create_dir_all(src.join("etc")).unwrap();
    std::fs::write(src.join("etc/hello"), "from zstd").unwrap();
    let blob = base.join("layer");
    let ok = Command::new(r"C:\Windows\System32\tar.exe").arg("--zstd").arg("-c").arg("-f").arg(&blob)
        .arg("-C").arg(&src).arg("etc").status().unwrap().success();
    assert!(ok, "tar.exe can't write zstd here");
    let plain = zstd_to_tar(&blob).unwrap();
    let root = base.join("root");
    fs::unpack(&plain, &root).unwrap();
    assert_eq!(std::fs::read_to_string(root.join("etc/hello")).unwrap(), "from zstd");
    std::fs::remove_dir_all(base).unwrap();
}
