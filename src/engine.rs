//! `lx engine [pipe]`: the Docker Engine API on a named pipe, so the docker CLI, docker compose and other
//! Docker clients drive lx (`DOCKER_HOST=npipe:////./pipe/lx_engine`). Each container is an `lx run` child
//! of the engine, each exec an `lx exec`; the engine keeps what Docker keeps about them (state, exit code,
//! output) and serves create/start/attach/wait/logs/stop/kill/rm/inspect/ps, exec, images and pull.
//! ponytail: state lives in the engine's memory (gone when it stops); networks are names only (all
//! containers share the host's); no build, no events, no stats.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const API: &str = "1.43";
const VERSION: &str = "24.0.0-lx";

#[repr(C)]
struct Overlapped {
    internal: [usize; 2],
    offset: u32,
    offset_high: u32,
    event: isize,
}

/// One client connection. Overlapped, so a hijacked stream can read stdin while output is written.
struct Pipe(isize);
unsafe impl Send for Pipe {}
unsafe impl Sync for Pipe {}

impl Pipe {
    fn io(&self, buf: *mut u8, len: usize, write: bool) -> std::io::Result<usize> {
        use crate::win::*;
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        let mut o = Overlapped { internal: [0; 2], offset: 0, offset_high: 0, event: ev };
        let op = (&mut o as *mut Overlapped).cast();
        let mut done = 0u32;
        let len = len.min(1 << 20) as u32;
        let mut ok = unsafe { if write { WriteFile(self.0, buf, len, &mut done, op) } else { ReadFile(self.0, buf, len, &mut done, op) } } != 0;
        let mut err = if ok { 0 } else { unsafe { GetLastError() } };
        if err == 997 { // ERROR_IO_PENDING
            ok = unsafe { GetOverlappedResult(self.0, op, &mut done, 1) } != 0;
            err = if ok { 0 } else { unsafe { GetLastError() } };
        }
        unsafe { CloseHandle(ev) };
        match err {
            0 => Ok(done as usize),
            109 | 232 if !write => Ok(0), // the client hung up: end of input
            e => Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }

    fn send(&self, mut b: &[u8]) -> std::io::Result<()> {
        while !b.is_empty() {
            let n = self.io(b.as_ptr() as *mut u8, b.len(), true)?;
            b = &b[n..];
        }
        Ok(())
    }

    /// Wake a read blocked on this pipe (the hijacked stdin copier), so its thread ends.
    fn cancel(&self) {
        unsafe { crate::win::CancelIoEx(self.0, std::ptr::null_mut()) };
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe { crate::win::CloseHandle(self.0) };
    }
}

pub fn serve(name: Option<&str>) -> Result<(), String> {
    use crate::win::*;
    let name = name.unwrap_or("lx_engine");
    let path: Vec<u16> = format!(r"\\.\pipe\{name}").encode_utf16().chain([0]).collect();
    eprintln!("[lx] Docker Engine API on npipe:////./pipe/{name}  (DOCKER_HOST=npipe:////./pipe/{name})");
    let mut first = 0x0008_0000; // FILE_FLAG_FIRST_PIPE_INSTANCE: fail if someone else serves this name
    loop {
        // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED; byte mode; unlimited instances
        let h = unsafe { CreateNamedPipeW(path.as_ptr(), 3 | 0x4000_0000 | first, 0, 255, 65536, 65536, 0, std::ptr::null_mut()) };
        if h == -1 {
            return Err(format!("can't serve \\\\.\\pipe\\{name} (Windows error {}; another engine running?)", unsafe { GetLastError() }));
        }
        first = 0;
        let ev = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        let mut o = Overlapped { internal: [0; 2], offset: 0, offset_high: 0, event: ev };
        let op = (&mut o as *mut Overlapped).cast();
        let connected = unsafe { ConnectNamedPipe(h, op) } != 0 || match unsafe { GetLastError() } {
            535 => true, // ERROR_PIPE_CONNECTED: the client came first
            997 => (unsafe { GetOverlappedResult(h, op, &mut 0, 1) }) != 0,
            _ => false,
        };
        unsafe { CloseHandle(ev) };
        let p = Arc::new(Pipe(h));
        if connected {
            std::thread::spawn(move || connection(p));
        }
    }
}

// ---- HTTP/1.1 ----

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

impl Req {
    fn q(&self, k: &str) -> &str {
        self.query.get(k).map_or("", String::as_str)
    }
    fn flag(&self, k: &str) -> bool {
        matches!(self.q(k), "1" | "true" | "True")
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

struct Conn {
    p: Arc<Pipe>,
    buf: Vec<u8>,
}

impl Conn {
    fn fill(&mut self) -> bool {
        let mut b = [0u8; 16384];
        match self.p.io(b.as_mut_ptr(), b.len(), false) {
            Ok(n) if n > 0 => {
                self.buf.extend_from_slice(&b[..n]);
                true
            }
            _ => false,
        }
    }
    fn line(&mut self) -> Option<String> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let l = String::from_utf8_lossy(&self.buf[..i]).into_owned();
                self.buf.drain(..i + 2);
                return Some(l);
            }
            if !self.fill() {
                return None;
            }
        }
    }
    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        while self.buf.len() < n {
            if !self.fill() {
                return None;
            }
        }
        Some(self.buf.drain(..n).collect())
    }
    fn request(&mut self) -> Option<Req> {
        let first = self.line()?;
        let mut words = first.split(' ');
        let (method, target) = (words.next()?.to_string(), words.next()?.to_string());
        let mut headers = HashMap::new();
        loop {
            let l = self.line()?;
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let mut body = Vec::new();
        if headers.get("transfer-encoding").is_some_and(|t| t.eq_ignore_ascii_case("chunked")) {
            loop {
                let size = usize::from_str_radix(self.line()?.split(';').next()?.trim(), 16).ok()?;
                if size == 0 {
                    while !self.line()?.is_empty() {} // trailers
                    break;
                }
                body.extend(self.take(size)?);
                self.line()?;
            }
        } else if let Some(n) = headers.get("content-length").and_then(|n| n.parse().ok()) {
            body = self.take(n)?;
        }
        let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
        // Clients prefix the API version: /v1.43/containers/json.
        let path = match path.strip_prefix("/v").and_then(|r| r.split_once('/')) {
            Some((v, rest)) if v.contains('.') && v.chars().all(|c| c.is_ascii_digit() || c == '.') => format!("/{rest}"),
            _ => path.to_string(),
        };
        let query = qs.split('&').filter_map(|kv| kv.split_once('=').or(Some((kv, "")))).filter(|(k, _)| !k.is_empty())
            .map(|(k, v)| (unescape(k), unescape(v))).collect();
        Some(Req { method, path: unescape(&path), query, body })
    }
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn reason(code: u16) -> &'static str {
    match code {
        101 => "UPGRADED",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    }
}

fn head(code: u16, extra: &str) -> String {
    format!("HTTP/1.1 {code} {}\r\nApi-Version: {API}\r\nDocker-Experimental: false\r\nOstype: linux\r\nServer: lx/{VERSION}\r\n{extra}\r\n", reason(code))
}

fn respond(p: &Pipe, code: u16, ctype: &str, body: &[u8]) {
    let h = head(code, &format!("Content-Type: {ctype}\r\nContent-Length: {}\r\n", body.len()));
    let _ = p.send(&[h.as_bytes(), body].concat());
}

fn reply(p: &Pipe, code: u16, v: Value) {
    respond(p, code, "application/json", format!("{v}\n").as_bytes());
}

fn fail(p: &Pipe, code: u16, msg: &str) {
    reply(p, code, json!({ "message": msg }));
}

/// Headers now, body until we close: for answers that come later (wait) or stream (logs, attach).
fn open_stream(p: &Pipe, code: u16, ctype: &str, upgrade: bool) {
    let extra = if upgrade { format!("Content-Type: {ctype}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n") } else { format!("Content-Type: {ctype}\r\nConnection: close\r\n") };
    let _ = p.send(head(code, &extra).as_bytes());
}

fn connection(p: Arc<Pipe>) {
    let mut c = Conn { p: p.clone(), buf: Vec::new() };
    while let Some(req) = c.request() {
        if !route(&req, &mut c) {
            break; // hijacked or streamed: the connection is done
        }
    }
}

// ---- running processes: a container's `lx run` or an exec's `lx exec` ----

#[derive(Default)]
struct RunState {
    pid: u32,
    started: Option<SystemTime>,
    finished: Option<SystemTime>,
    code: Option<i32>,
    out: Vec<(u8, Vec<u8>)>, // (1 stdout | 2 stderr, bytes)
    sinks: Vec<(Arc<Pipe>, bool)>, // attached clients: (pipe, tty: raw instead of multiplexed frames)
    stdin: Option<std::process::ChildStdin>,
    pending: Vec<u8>, // stdin that came before the process
    stdin_done: bool,
}

#[derive(Default)]
struct Run {
    s: Mutex<RunState>,
    cv: Condvar,
}

impl Run {
    fn running(&self) -> bool {
        let s = self.s.lock().unwrap();
        s.started.is_some() && s.code.is_none()
    }

    fn push(&self, stream: u8, data: &[u8]) {
        let mut s = self.s.lock().unwrap();
        s.out.push((stream, data.to_vec()));
        s.sinks.retain(|(p, tty)| p.send(&frame(stream, data, *tty)).is_ok());
        self.cv.notify_all();
    }

    fn feed(&self, data: &[u8]) {
        let mut s = self.s.lock().unwrap();
        match s.stdin.as_mut() {
            Some(w) => {
                let _ = w.write_all(data);
            }
            None => s.pending.extend_from_slice(data),
        }
    }

    fn close_stdin(&self) {
        let mut s = self.s.lock().unwrap();
        s.stdin = None;
        s.stdin_done = true;
    }

    /// Until the process has run and exited.
    fn wait(&self) -> i32 {
        let mut s = self.s.lock().unwrap();
        while s.code.is_none() {
            s = self.cv.wait(s).unwrap();
        }
        s.code.unwrap_or(0)
    }
}

fn frame(stream: u8, data: &[u8], tty: bool) -> Vec<u8> {
    if tty {
        return data.to_vec();
    }
    let mut f = vec![stream, 0, 0, 0];
    f.extend((data.len() as u32).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// Start `lx <args>` for `run`; `exited` runs once it has ended and its output is all in.
fn spawn(run: &Arc<Run>, args: &[String], stdin: bool, exited: impl FnOnce() + Send + 'static) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .args(args)
        .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x200) // CREATE_NEW_PROCESS_GROUP: the engine's Ctrl-C isn't theirs
        .spawn()
        .map_err(|e| e.to_string())?;
    {
        let mut s = run.s.lock().unwrap();
        (s.pid, s.started, s.finished, s.code) = (child.id(), Some(SystemTime::now()), None, None);
        s.stdin = child.stdin.take();
        let pending = std::mem::take(&mut s.pending);
        if let Some(w) = s.stdin.as_mut() {
            let _ = w.write_all(&pending);
        }
        if s.stdin_done {
            s.stdin = None;
        }
    }
    let pumps: Vec<_> = [(1u8, child.stdout.take().map(|r| Box::new(r) as Box<dyn Read + Send>)), (2, child.stderr.take().map(|r| Box::new(r) as Box<dyn Read + Send>))]
        .into_iter()
        .filter_map(|(stream, r)| r.map(|r| (stream, r)))
        .map(|(stream, mut r)| {
            let run = run.clone();
            std::thread::spawn(move || {
                let mut b = vec![0u8; 32768];
                while let Ok(n) = r.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    run.push(stream, &b[..n]);
                }
            })
        })
        .collect();
    let run = run.clone();
    std::thread::spawn(move || {
        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(137);
        for p in pumps {
            let _ = p.join();
        }
        {
            let mut s = run.s.lock().unwrap();
            (s.code, s.finished, s.stdin) = (Some(code), Some(SystemTime::now()), None);
        }
        exited();
        run.cv.notify_all();
    });
    Ok(())
}

/// Hijacked stream (attach, exec start): output to the client as it comes, client input to stdin, until
/// the process ends. `replay`: the output so far first (attach with logs=1).
fn hijack(c: &mut Conn, run: &Arc<Run>, tty: bool, stdin: bool, replay: bool, ready: Option<std::sync::mpsc::Sender<()>>) {
    let ctype = if tty { "application/vnd.docker.raw-stream" } else { "application/vnd.docker.multiplexed-stream" };
    open_stream(&c.p, 101, ctype, true);
    {
        let mut s = run.s.lock().unwrap();
        if replay {
            for (stream, d) in &s.out {
                let _ = c.p.send(&frame(*stream, d, tty));
            }
        }
        s.sinks.push((c.p.clone(), tty));
    }
    if let Some(r) = ready {
        let _ = r.send(()); // attached: the process may start now
    }
    let copier = stdin.then(|| {
        let (run, mut conn) = (run.clone(), Conn { p: c.p.clone(), buf: std::mem::take(&mut c.buf) });
        std::thread::spawn(move || {
            if !conn.buf.is_empty() {
                run.feed(&std::mem::take(&mut conn.buf));
            }
            while conn.fill() {
                run.feed(&std::mem::take(&mut conn.buf));
            }
            run.close_stdin(); // the client closed its input (docker run -i < file)
        })
    });
    run.wait();
    run.s.lock().unwrap().sinks.retain(|(p, _)| !Arc::ptr_eq(p, &c.p));
    if let Some(t) = copier {
        c.p.cancel();
        let _ = t.join();
    }
}

// ---- containers ----

struct Container {
    id: String,
    name: String,
    created: SystemTime,
    body: Value, // the create request: Image, Cmd, Env, HostConfig, Labels, ...
    run: Arc<Run>,
}

static CONTAINERS: Mutex<Vec<Arc<Container>>> = Mutex::new(Vec::new());
static EXECS: Mutex<Vec<(String, Arc<Container>, Value, Arc<Run>)>> = Mutex::new(Vec::new());
static NETWORKS: Mutex<Vec<Value>> = Mutex::new(Vec::new());

fn new_id() -> String {
    let mut b = [0u8; 32];
    let _ = crate::syscall::getrandom(b.as_mut_ptr() as u64, 32);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// By full id, unique id prefix, or name (with or without Docker's leading '/').
fn find(key: &str) -> Option<Arc<Container>> {
    let all = CONTAINERS.lock().unwrap();
    let key = key.trim_start_matches('/');
    if let Some(c) = all.iter().find(|c| c.id == key || c.name == key) {
        return Some(c.clone());
    }
    let mut by_prefix = all.iter().filter(|c| !key.is_empty() && c.id.starts_with(key));
    match (by_prefix.next(), by_prefix.next()) {
        (Some(c), None) => Some(c.clone()),
        _ => None,
    }
}

fn image_exists(name: &str) -> bool {
    crate::image::Ref::parse(name).dir().join("config.json").exists()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
}

/// The `lx run` command line for a create request.
fn run_args(c: &Container) -> Vec<String> {
    let (b, hc) = (&c.body, &c.body["HostConfig"]);
    let mut a = vec!["run".to_string(), "--name".into(), c.name.clone()];
    for e in strs(&b["Env"]) {
        a.extend(["-e".into(), e]);
    }
    for (flag, key) in [("-w", "WorkingDir"), ("-u", "User")] {
        if let Some(v) = b[key].as_str().filter(|v| !v.is_empty()) {
            a.extend([flag.into(), v.into()]);
        }
    }
    for bind in strs(&hc["Binds"]) {
        // A named volume (`data:/x`) lives under rootfs/volumes, a host path is used as it is.
        let named = bind.split(':').next().is_some_and(|h| !h.is_empty() && !h.contains(['/', '\\']) && h.len() > 1);
        let bind = if named {
            let (n, rest) = bind.split_once(':').unwrap_or((&bind, ""));
            let dir = std::path::Path::new("rootfs/volumes").join(n);
            let _ = std::fs::create_dir_all(&dir);
            let abs = std::fs::canonicalize(&dir).map(|p| p.to_string_lossy().trim_start_matches(r"\\?\").to_string()).unwrap_or_default();
            format!("{abs}:{rest}")
        } else {
            bind
        };
        a.extend(["-v".into(), bind]);
    }
    if let Some(ports) = hc["PortBindings"].as_object() {
        for (cport, binds) in ports {
            let (num, proto) = cport.split_once('/').unwrap_or((cport, "tcp"));
            for bnd in binds.as_array().into_iter().flatten() {
                let host = bnd["HostPort"].as_str().filter(|h| !h.is_empty()).unwrap_or(num);
                let ip = bnd["HostIp"].as_str().filter(|i| !i.is_empty() && *i != "0.0.0.0" && *i != "::");
                let suffix = if proto == "udp" { "/udp" } else { "" };
                a.extend(["-p".into(), match ip { Some(ip) => format!("{ip}:{host}:{num}{suffix}"), None => format!("{host}:{num}{suffix}") }]);
            }
        }
    }
    for h in strs(&hc["ExtraHosts"]) {
        a.extend(["--add-host".into(), h]);
    }
    if let Some(m) = hc["Memory"].as_u64().filter(|&m| m > 0) {
        a.extend(["-m".into(), m.to_string()]);
    }
    // Entrypoint: [] or [""] resets it; otherwise its first word is the program, the rest go before Cmd.
    let mut cmd = strs(&b["Cmd"]);
    if b["Entrypoint"].is_array() {
        let ep = strs(&b["Entrypoint"]);
        a.extend(["--entrypoint".into(), ep.first().cloned().unwrap_or_default()]);
        cmd = ep.iter().skip(1).cloned().chain(cmd).collect();
    }
    a.push(b["Image"].as_str().unwrap_or_default().to_string());
    a.extend(cmd);
    a
}

fn start(c: &Arc<Container>) -> Result<(), String> {
    let stdin = c.body["OpenStdin"].as_bool().unwrap_or(false);
    let auto_remove = c.body["HostConfig"]["AutoRemove"].as_bool().unwrap_or(false);
    let me = c.clone();
    spawn(&c.run, &run_args(c), stdin, move || {
        if auto_remove {
            CONTAINERS.lock().unwrap().retain(|x| !Arc::ptr_eq(x, &me));
        }
    })
}

fn rfc3339(t: Option<SystemTime>) -> String {
    let Some(t) = t else { return "0001-01-01T00:00:00Z".into() };
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil_from_days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn ago(t: Option<SystemTime>) -> String {
    let s = t.and_then(|t| t.elapsed().ok()).unwrap_or_default().as_secs();
    match s {
        0..=59 => format!("{s} seconds"),
        60..=3599 => format!("{} minutes", s / 60),
        _ => format!("{} hours", s / 3600),
    }
}

fn state(c: &Container) -> (&'static str, String) {
    let s = c.run.s.lock().unwrap();
    match (s.started, s.code) {
        (None, _) => ("created", "Created".into()),
        (Some(t), None) => ("running", format!("Up {}", ago(Some(t)))),
        (_, Some(code)) => ("exited", format!("Exited ({code}) {} ago", ago(s.finished))),
    }
}

fn ports(c: &Container) -> Vec<Value> {
    let mut v = Vec::new();
    for (cport, binds) in c.body["HostConfig"]["PortBindings"].as_object().into_iter().flatten() {
        let (num, proto) = cport.split_once('/').unwrap_or((cport, "tcp"));
        let num: u16 = num.parse().unwrap_or(0);
        for b in binds.as_array().into_iter().flatten() {
            let host: u16 = b["HostPort"].as_str().and_then(|h| h.parse().ok()).unwrap_or(num);
            v.push(json!({ "IP": "0.0.0.0", "PrivatePort": num, "PublicPort": host, "Type": proto }));
        }
    }
    v
}

fn summary(c: &Container) -> Value {
    let (st, status) = state(c);
    let cmd = strs(&c.body["Entrypoint"]).into_iter().chain(strs(&c.body["Cmd"])).collect::<Vec<_>>().join(" ");
    json!({
        "Id": c.id, "Names": [format!("/{}", c.name)], "Image": c.body["Image"], "ImageID": image_id(c.body["Image"].as_str().unwrap_or("")),
        "Command": cmd, "Created": unix(c.created), "State": st, "Status": status, "Ports": ports(c),
        "Labels": c.body["Labels"].as_object().cloned().unwrap_or_default(), "SizeRw": 0, "SizeRootFs": 0,
        "HostConfig": { "NetworkMode": c.body["HostConfig"]["NetworkMode"].as_str().unwrap_or("default") },
        "NetworkSettings": { "Networks": networks_of(c) }, "Mounts": [],
    })
}

fn networks_of(c: &Container) -> Value {
    let mode = c.body["HostConfig"]["NetworkMode"].as_str().unwrap_or("bridge");
    let mut nets = serde_json::Map::new();
    let names: Vec<String> = c.body["NetworkingConfig"]["EndpointsConfig"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    for n in if names.is_empty() { vec![if mode == "default" { "bridge".to_string() } else { mode.to_string() }] } else { names } {
        nets.insert(n.clone(), json!({ "IPAddress": "127.0.0.1", "Gateway": "", "NetworkID": n, "Aliases": [c.name] }));
    }
    Value::Object(nets)
}

fn inspect(c: &Container) -> Value {
    let (st, _) = state(c);
    let s = c.run.s.lock().unwrap();
    let mut config = c.body.clone();
    config["Hostname"] = json!(&c.id[..12]);
    config["Labels"] = json!(c.body["Labels"].as_object().cloned().unwrap_or_default());
    let path = strs(&c.body["Entrypoint"]).into_iter().chain(strs(&c.body["Cmd"])).collect::<Vec<_>>();
    json!({
        "Id": c.id, "Created": rfc3339(Some(c.created)), "Path": path.first().cloned().unwrap_or_default(), "Args": path.iter().skip(1).collect::<Vec<_>>(),
        "State": { "Status": st, "Running": st == "running", "Paused": false, "Restarting": false, "OOMKilled": false, "Dead": false,
                   "Pid": if st == "running" { s.pid } else { 0 }, "ExitCode": s.code.unwrap_or(0), "Error": "",
                   "StartedAt": rfc3339(s.started), "FinishedAt": rfc3339(s.finished) },
        "Image": image_id(c.body["Image"].as_str().unwrap_or("")), "Name": format!("/{}", c.name), "RestartCount": 0, "Driver": "lx", "Platform": "linux",
        "Config": config, "HostConfig": c.body["HostConfig"], "Mounts": [],
        "NetworkSettings": { "Ports": {}, "Networks": networks_of(c), "IPAddress": "127.0.0.1" },
    })
}

fn image_id(name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    crate::image::Ref::parse(name).dir().hash(&mut h);
    format!("sha256:{}", format!("{:016x}", h.finish()).repeat(4)) // ponytail: stable per image, not its digest
}

fn matches_filters(c: &Container, filters: &Value) -> bool {
    let labels = &c.body["Labels"];
    let ok = |key: &str, test: &dyn Fn(&str) -> bool| strs(&filters[key]).iter().all(|v| test(v))
        && filters[key].as_object().is_none_or(|m| m.keys().all(|v| test(v))); // both filter encodings
    ok("label", &|l| match l.split_once('=') {
        Some((k, v)) => labels[k].as_str() == Some(v),
        None => !labels[l].is_null(),
    }) && ok("name", &|n| c.name.contains(n.trim_start_matches('/')))
        && ok("id", &|i| c.id.starts_with(i))
        && ok("status", &|s| state(c).0 == s)
}

// ---- routes ----

/// Handle one request; false when the connection was taken over (hijack, stream) and is done.
fn route(r: &Req, c: &mut Conn) -> bool {
    let p = c.p.clone();
    let parts: Vec<&str> = r.path.trim_start_matches('/').split('/').collect();
    let m = r.method.as_str();
    match (m, parts.as_slice()) {
        ("GET" | "HEAD", ["_ping"]) => respond(&p, 200, "text/plain; charset=utf-8", if m == "HEAD" { b"" } else { b"OK" }),
        ("GET", ["version"]) => reply(&p, 200, json!({
            "Version": VERSION, "ApiVersion": API, "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.6.0-lx",
            "GitCommit": "lx", "GoVersion": "none (lx is Rust)", "BuildTime": "", "Platform": { "Name": "lx" },
            "Components": [{ "Name": "Engine", "Version": VERSION, "Details": { "ApiVersion": API, "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64" } }],
        })),
        ("GET", ["info"]) => {
            let all = CONTAINERS.lock().unwrap().clone();
            let running = all.iter().filter(|c| c.run.running()).count();
            reply(&p, 200, json!({
                "ID": "lx", "Name": "lx", "ServerVersion": VERSION, "OperatingSystem": "lx (Linux images as native Windows processes)",
                "OSType": "linux", "Architecture": "x86_64", "KernelVersion": "6.6.0-lx", "Driver": "lx",
                "Containers": all.len(), "ContainersRunning": running, "ContainersPaused": 0, "ContainersStopped": all.len() - running,
                "Images": crate::image::list().len(), "NCPU": std::thread::available_parallelism().map_or(1, |n| n.get()),
                "MemTotal": 0, "DockerRootDir": "rootfs", "IndexServerAddress": "https://index.docker.io/v1/",
                "Plugins": { "Volume": [], "Network": ["bridge"], "Log": [] }, "SecurityOptions": [], "Warnings": [],
            }))
        }
        // -- images --
        ("GET", ["images", "json"]) => reply(&p, 200, Value::Array(crate::image::list().into_iter().map(|(repo, tag)| {
            let name = format!("{repo}:{tag}");
            // ponytail: when it was pulled, not the image's own date; no size
            let created = std::fs::metadata(crate::image::Ref::parse(&name).dir().join("config.json")).and_then(|m| m.modified()).map_or(0, unix);
            json!({ "Id": image_id(&name), "ParentId": "", "RepoTags": [name], "RepoDigests": [], "Created": created, "Size": 0,
                    "SharedSize": -1, "VirtualSize": 0, "Labels": {}, "Containers": -1 })
        }).collect())),
        ("POST", ["images", "create"]) => {
            let (from, tag) = (r.q("fromImage"), r.q("tag"));
            let name = if tag.is_empty() || from.contains('@') { from.to_string() } else if tag.starts_with("sha256:") { format!("{from}@{tag}") } else { format!("{from}:{tag}") };
            let out = match crate::image::pull(&crate::image::Ref::parse(&name)) {
                Ok(_) => format!("{}\n{}\n", json!({ "status": format!("Pulling from {from}"), "id": tag }), json!({ "status": format!("Status: Downloaded newer image for {name}") })),
                Err(e) => format!("{}\n", json!({ "errorDetail": { "message": e }, "error": e })),
            };
            respond(&p, 200, "application/json", out.as_bytes());
        }
        ("GET", ["images", name @ .., "json"]) if !name.is_empty() => {
            let name = name.join("/");
            let dir = crate::image::Ref::parse(&name).dir();
            match std::fs::read(dir.join("config.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
                Some(cfg) => reply(&p, 200, json!({ "Id": image_id(&name), "RepoTags": [name], "RepoDigests": [], "Parent": "", "Created": cfg["created"],
                    "Config": cfg["config"], "Os": "linux", "Architecture": "amd64", "Size": 0, "VirtualSize": 0, "RootFS": { "Type": "layers", "Layers": [] } })),
                None => fail(&p, 404, &format!("No such image: {name}")),
            }
        }
        ("DELETE", ["images", name @ ..]) if !name.is_empty() => {
            let name = name.join("/");
            let dir = crate::image::Ref::parse(&name).dir();
            if !dir.join("config.json").exists() {
                fail(&p, 404, &format!("No such image: {name}"));
            } else if let Err(e) = std::fs::remove_dir_all(&dir) {
                fail(&p, 500, &e.to_string());
            } else {
                reply(&p, 200, json!([{ "Untagged": name }]));
            }
        }
        // -- containers --
        ("GET", ["containers", "json"]) => {
            let filters: Value = serde_json::from_str(r.q("filters")).unwrap_or(Value::Null);
            let all = CONTAINERS.lock().unwrap().clone();
            reply(&p, 200, Value::Array(all.iter().filter(|c| (r.flag("all") || c.run.running()) && matches_filters(c, &filters)).map(|c| summary(c)).collect()));
        }
        ("POST", ["containers", "create"]) => {
            let body = r.json();
            let image = body["Image"].as_str().unwrap_or_default().to_string();
            let name = r.q("name").trim_start_matches('/').to_string();
            if !image_exists(&image) {
                fail(&p, 404, &format!("No such image: {image}"));
            } else if !name.is_empty() && find(&name).is_some_and(|c| c.name == name) {
                fail(&p, 409, &format!("Conflict. The container name \"/{name}\" is already in use"));
            } else {
                let id = new_id();
                let name = if name.is_empty() { format!("lx_{}", &id[..8]) } else { name };
                CONTAINERS.lock().unwrap().push(Arc::new(Container { id: id.clone(), name, created: SystemTime::now(), body, run: Arc::default() }));
                reply(&p, 201, json!({ "Id": id, "Warnings": [] }));
            }
        }
        (_, ["containers", id, action @ ..]) => {
            let Some(ct) = find(id) else {
                fail(&p, 404, &format!("No such container: {id}"));
                return true;
            };
            return container_route(m, action, r, c, &ct);
        }
        ("POST", ["exec", id, "start"]) => {
            let Some((ct, body, run)) = EXECS.lock().unwrap().iter().find(|e| e.0 == *id).map(|e| (e.1.clone(), e.2.clone(), e.3.clone())) else {
                fail(&p, 404, &format!("No such exec instance: {id}"));
                return true;
            };
            let start = r.json();
            let pid = ct.run.s.lock().unwrap().pid;
            let mut a = vec!["exec".to_string()];
            for e in strs(&body["Env"]) {
                a.extend(["-e".into(), e]);
            }
            for (flag, key) in [("-w", "WorkingDir"), ("-u", "User")] {
                if let Some(v) = body[key].as_str().filter(|v| !v.is_empty()) {
                    a.extend([flag.into(), v.into()]);
                }
            }
            a.push(pid.to_string());
            a.extend(strs(&body["Cmd"]));
            let stdin = body["AttachStdin"].as_bool().unwrap_or(false);
            let tty = start["Tty"].as_bool().or(body["Tty"].as_bool()).unwrap_or(false);
            if start["Detach"].as_bool().unwrap_or(false) {
                match spawn(&run, &a, false, || {}) {
                    Ok(()) => respond(&p, 200, "application/json", b""),
                    Err(e) => fail(&p, 500, &e),
                }
                return true;
            }
            // Attach first, so no output is missed, then start.
            let sink_run = run.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let a2 = a.clone();
            std::thread::spawn(move || {
                let _ = rx.recv(); // the client is attached
                if let Err(e) = spawn(&sink_run, &a2, stdin, || {}) {
                    sink_run.push(2, format!("lx exec: {e}\n").as_bytes());
                    let mut s = sink_run.s.lock().unwrap();
                    (s.code, s.started) = (Some(126), Some(SystemTime::now()));
                    sink_run.cv.notify_all();
                }
            });
            hijack(c, &run, tty, stdin, false, Some(tx));
            return false;
        }
        ("GET", ["exec", id, "json"]) => match EXECS.lock().unwrap().iter().find(|e| e.0 == *id) {
            Some((id, ct, body, run)) => {
                let s = run.s.lock().unwrap();
                let cmd = strs(&body["Cmd"]);
                reply(&p, 200, json!({ "ID": id, "ContainerID": ct.id, "Running": s.started.is_some() && s.code.is_none(), "ExitCode": s.code,
                    "Pid": s.pid, "OpenStdin": body["AttachStdin"], "OpenStdout": true, "OpenStderr": true,
                    "ProcessConfig": { "entrypoint": cmd.first(), "arguments": cmd.iter().skip(1).collect::<Vec<_>>(), "tty": body["Tty"], "privileged": false } }))
            }
            None => fail(&p, 404, &format!("No such exec instance: {id}")),
        },
        ("POST", ["exec", _, "resize"]) => respond(&p, 200, "text/plain", b""),
        // -- networks: names and labels only; every container shares the host's network --
        ("GET", ["networks"]) => {
            let mut v = vec![json!({ "Name": "bridge", "Id": "bridge", "Driver": "bridge", "Scope": "local", "Labels": {}, "Containers": {} })];
            v.extend(NETWORKS.lock().unwrap().iter().cloned());
            reply(&p, 200, Value::Array(v));
        }
        ("POST", ["networks", "create"]) => {
            let b = r.json();
            let name = b["Name"].as_str().unwrap_or_default().to_string();
            let net = json!({ "Name": name, "Id": name, "Driver": b["Driver"].as_str().unwrap_or("bridge"), "Scope": "local",
                              "Labels": b["Labels"].as_object().cloned().unwrap_or_default(), "Containers": {}, "Options": {}, "IPAM": { "Config": [] } });
            NETWORKS.lock().unwrap().push(net);
            reply(&p, 201, json!({ "Id": name, "Warning": "" }));
        }
        ("GET", ["networks", id]) => {
            let nets = NETWORKS.lock().unwrap();
            match nets.iter().find(|n| n["Id"] == *id || n["Name"] == *id) {
                Some(n) => reply(&p, 200, n.clone()),
                None if *id == "bridge" => reply(&p, 200, json!({ "Name": "bridge", "Id": "bridge", "Driver": "bridge", "Scope": "local", "Labels": {}, "Containers": {} })),
                None => fail(&p, 404, &format!("network {id} not found")),
            }
        }
        ("DELETE", ["networks", id]) => {
            NETWORKS.lock().unwrap().retain(|n| n["Id"] != *id && n["Name"] != *id);
            respond(&p, 204, "text/plain", b"");
        }
        ("POST", ["networks", _, "connect" | "disconnect"]) => respond(&p, 200, "text/plain", b""),
        ("GET", ["volumes"]) => reply(&p, 200, json!({ "Volumes": [], "Warnings": [] })),
        // ponytail: an events stream that stays open and quiet (clients that watch it still work).
        ("GET", ["events"]) => {
            open_stream(&p, 200, "application/json", false);
            while c.fill() {
                c.buf.clear();
            }
            return false;
        }
        _ => fail(&p, 404, &format!("page not found: {} {} (not in lx's Engine API yet)", r.method, r.path)),
    }
    true
}

fn container_route(m: &str, action: &[&str], r: &Req, c: &mut Conn, ct: &Arc<Container>) -> bool {
    let p = c.p.clone();
    match (m, action) {
        ("GET", ["json"]) => reply(&p, 200, inspect(ct)),
        ("POST", ["start"]) => {
            if ct.run.running() {
                respond(&p, 304, "text/plain", b"");
            } else {
                match start(ct) {
                    Ok(()) => respond(&p, 204, "text/plain", b""),
                    Err(e) => fail(&p, 500, &e),
                }
            }
        }
        ("POST", ["attach"]) => {
            let tty = ct.body["Tty"].as_bool().unwrap_or(false);
            let stdin = r.flag("stdin") && ct.body["OpenStdin"].as_bool().unwrap_or(false);
            hijack(c, &ct.run, tty, stdin, r.flag("logs"), None);
            return false;
        }
        ("POST", ["wait"]) => {
            open_stream(&p, 200, "application/json", false);
            let code = ct.run.wait();
            let _ = p.send(format!("{}\n", json!({ "StatusCode": code, "Error": null })).as_bytes());
            return false;
        }
        ("GET", ["logs"]) => {
            let tty = ct.body["Tty"].as_bool().unwrap_or(false);
            let want = |s: u8| if s == 1 { r.flag("stdout") } else { r.flag("stderr") };
            open_stream(&p, 200, if tty { "application/vnd.docker.raw-stream" } else { "application/vnd.docker.multiplexed-stream" }, false);
            let mut s = ct.run.s.lock().unwrap();
            // tail=N: the last N lines.
            let mut lines: Vec<(u8, Vec<u8>)> = Vec::new();
            for (stream, d) in s.out.iter().filter(|(st, _)| want(*st)) {
                for piece in d.split_inclusive(|&b| b == b'\n') {
                    match lines.last_mut() {
                        Some((st, l)) if *st == *stream && l.last() != Some(&b'\n') => l.extend_from_slice(piece),
                        _ => lines.push((*stream, piece.to_vec())),
                    }
                }
            }
            let skip = r.q("tail").parse::<usize>().map_or(0, |n| lines.len().saturating_sub(n));
            for (stream, l) in &lines[skip..] {
                let _ = p.send(&frame(*stream, l, tty));
            }
            if r.flag("follow") && s.started.is_some() && s.code.is_none() {
                if r.flag("stdout") && r.flag("stderr") {
                    s.sinks.push((p.clone(), tty));
                    drop(s);
                    ct.run.wait();
                    ct.run.s.lock().unwrap().sinks.retain(|(x, _)| !Arc::ptr_eq(x, &p));
                } else {
                    // One stream only: poll the buffer (ponytail: sinks carry no stream filter).
                    let mut seen = s.out.len();
                    while s.code.is_none() {
                        s = ct.run.cv.wait(s).unwrap();
                        for (stream, d) in s.out[seen..].iter().filter(|(st, _)| want(*st)) {
                            let _ = p.send(&frame(*stream, d, tty));
                        }
                        seen = s.out.len();
                    }
                }
            }
            return false;
        }
        ("POST", ["stop" | "restart"]) => {
            let pid = ct.run.s.lock().unwrap().pid;
            let running = ct.run.running();
            if running {
                let t = r.q("t").parse().unwrap_or(10);
                let _ = crate::proc::stop(pid, Duration::from_secs(t));
                ct.run.wait();
            }
            if action == ["restart"] {
                if let Err(e) = start(ct) {
                    fail(&p, 500, &e);
                    return true;
                }
            } else if !running {
                respond(&p, 304, "text/plain", b"");
                return true;
            }
            respond(&p, 204, "text/plain", b"");
        }
        ("POST", ["kill"]) => {
            if !ct.run.running() {
                fail(&p, 409, &format!("Container {} is not running", ct.id));
            } else {
                let sig = crate::signal::parse(if r.q("signal").is_empty() { "KILL" } else { r.q("signal") }).unwrap_or(9);
                let _ = crate::proc::send(ct.run.s.lock().unwrap().pid, sig);
                respond(&p, 204, "text/plain", b"");
            }
        }
        ("DELETE", []) => {
            if ct.run.running() {
                if !r.flag("force") {
                    fail(&p, 409, &format!("You cannot remove a running container {}. Stop the container before attempting removal or force remove", ct.id));
                    return true;
                }
                let _ = crate::proc::send(ct.run.s.lock().unwrap().pid, 9);
                ct.run.wait();
            }
            CONTAINERS.lock().unwrap().retain(|x| !Arc::ptr_eq(x, ct));
            respond(&p, 204, "text/plain", b"");
        }
        ("POST", ["resize"]) => respond(&p, 200, "text/plain", b""),
        ("POST", ["exec"]) => {
            if !ct.run.running() {
                fail(&p, 409, &format!("Container {} is not running", ct.id));
            } else {
                let id = new_id();
                EXECS.lock().unwrap().push((id.clone(), ct.clone(), r.json(), Arc::default()));
                reply(&p, 201, json!({ "Id": id }));
            }
        }
        _ => fail(&p, 404, &format!("page not found: {} {} (not in lx's Engine API yet)", r.method, r.path)),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(unescape("%7B%22label%22%3A%5B%5D%7D"), r#"{"label":[]}"#);
        assert_eq!(unescape("a+b%2"), "a b%2");
        assert_eq!(frame(1, b"hi", false), [1, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);
        assert_eq!(rfc3339(Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))), "2023-11-14T22:13:20Z");
    }
}
