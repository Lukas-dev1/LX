# Broad check of a glibc (Debian) Python image under lx: one line per feature, then a summary.
# Run: lx run -v <repo>/guest:/t:ro python:3.12 python3 /t/debian_check.py
import sys, traceback

results = []
checks = []  # registered at import, run under the __main__ guard (spawn re-imports this file)


ONLY = sys.argv[1:]  # optional name filters: run only checks whose name contains one of them


def check(name):
    def wrap(fn):
        checks.append((name, fn))
        return fn
    return wrap


def run_checks():
    for name, fn in checks:
        if ONLY and not any(o in name for o in ONLY):
            continue
        print(f"... {name}", flush=True)
        try:
            detail = fn()
            results.append((name, True, detail or ""))
        except Exception as e:
            results.append((name, False, f"{type(e).__name__}: {e}"))
            traceback.print_exc()


@check("libc")
def _():
    import platform
    lib, ver = platform.libc_ver()
    assert lib == "glibc", lib
    return ver


@check("hashlib + zlib + bz2 + lzma")
def _():
    import hashlib, zlib, bz2, lzma
    data = b"lx" * 10000
    assert zlib.decompress(zlib.compress(data)) == data
    assert bz2.decompress(bz2.compress(data)) == data
    assert lzma.decompress(lzma.compress(data)) == data
    return hashlib.sha256(data).hexdigest()[:12]


@check("ssl (OpenSSL)")
def _():
    import ssl
    ctx = ssl.create_default_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    return ssl.OPENSSL_VERSION


@check("sqlite3 (file db)")
def _():
    import sqlite3, os
    path = "/tmp/check.db"
    db = sqlite3.connect(path)
    db.execute("create table t (k integer primary key, v text)")
    db.executemany("insert into t (v) values (?)", [(str(i),) for i in range(1000)])
    db.commit()
    n = db.execute("select count(*), sum(k) from t").fetchone()
    db.close()
    db = sqlite3.connect(path)
    assert db.execute("select count(*) from t").fetchone()[0] == 1000
    db.close()
    os.remove(path)
    return f"{n} sqlite {sqlite3.sqlite_version}"


@check("ctypes (libc via dlopen)")
def _():
    import ctypes, ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
    assert libc.strlen(b"hello") == 5
    return str(libc.getpid())


@check("decimal + fractions + math")
def _():
    from decimal import Decimal, getcontext
    from fractions import Fraction
    import math
    getcontext().prec = 50
    assert str(Decimal(1) / Decimal(7))[:10] == "0.14285714"
    assert Fraction(1, 3) + Fraction(1, 6) == Fraction(1, 2)
    return f"{math.factorial(30)}"[:10]


@check("zoneinfo + datetime")
def _():
    from zoneinfo import ZoneInfo
    from datetime import datetime, timezone
    t = datetime(2026, 7, 1, 12, tzinfo=timezone.utc).astimezone(ZoneInfo("Europe/Stockholm"))
    assert t.hour == 14, t
    return t.isoformat()


@check("uuid + secrets + random")
def _():
    import uuid, secrets, random
    assert len(secrets.token_hex(16)) == 32
    return str(uuid.uuid4())


@check("locale + unicode")
def _():
    import locale
    locale.setlocale(locale.LC_ALL, "C.UTF-8")
    s = "åäö ✓ 日本"
    assert s.encode("utf-8").decode() == s
    return locale.getlocale()[1] or "C"


@check("files: os.walk, shutil, tempfile, pathlib, chmod, stat")
def _():
    import os, shutil, tempfile, pathlib, stat
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "a/b").mkdir(parents=True)
    (d / "a/b/f.txt").write_text("x" * 100)
    os.chmod(d / "a/b/f.txt", 0o644)
    shutil.copytree(d / "a", d / "copy")
    os.symlink("f.txt", d / "copy/b/link")
    assert (d / "copy/b/link").read_text() == "x" * 100
    files = sum(len(fs) for _, _, fs in os.walk(d))
    st = os.stat(d / "copy/b/f.txt")
    assert stat.S_ISREG(st.st_mode) and st.st_size == 100
    shutil.rmtree(d)
    assert not d.exists()
    return f"{files} files walked"


@check("subprocess (bash, pipes, env, exit codes)")
def _():
    import subprocess
    out = subprocess.run(["bash", "-c", "echo $((6*7)) | tr 4 X; exit 3"], capture_output=True, text=True)
    assert out.stdout.strip() == "X2" and out.returncode == 3, out
    p = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    o, _ = p.communicate(b"through a pipe")
    assert o == b"through a pipe"
    return "ok"


@check("multiprocessing (fork pool)")
def _():
    import multiprocessing as mp
    with mp.get_context("fork").Pool(3) as pool:
        r = pool.starmap(pow, [(i, 2) for i in range(10)])
    assert r == [i * i for i in range(10)]
    return str(sum(r))


def _child(q):
    q.put("from child")


@check("multiprocessing (spawn)")
def _():
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_child, args=(q,))
    p.start()
    v = q.get(timeout=60)
    p.join(60)
    assert v == "from child" and p.exitcode == 0, (v, p.exitcode)
    return "ok"


@check("threads + concurrent.futures")
def _():
    from concurrent.futures import ThreadPoolExecutor
    import hashlib
    with ThreadPoolExecutor(8) as ex:
        r = list(ex.map(lambda i: hashlib.sha256(str(i).encode() * 1000).hexdigest(), range(200)))
    assert len(set(r)) == 200
    return "200 tasks on 8 threads"


@check("asyncio sockets (server + clients)")
def _():
    import asyncio

    async def main():
        async def handle(r, w):
            w.write((await r.readline()).upper())
            await w.drain()
            w.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]

        async def client(i):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"hi {i}\n".encode())
            await w.drain()
            line = await r.readline()
            w.close()
            return line
        out = await asyncio.gather(*(client(i) for i in range(20)))
        srv.close()
        await srv.wait_closed()
        return out
    out = asyncio.run(main())
    assert out == [f"HI {i}\n".encode() for i in range(20)]
    return "20 concurrent clients"


@check("threaded HTTP server + urllib")
def _():
    import http.server, threading, urllib.request

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            b = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    bodies = [urllib.request.urlopen(url, timeout=10).read() for _ in range(20)]
    srv.shutdown()
    assert bodies == [b"ok"] * 20
    return "20/20"


@check("DNS + HTTPS (certificate verification)")
def _():
    import urllib.request, socket
    socket.getaddrinfo("pypi.org", 443)
    with urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=30) as r:
        assert r.status == 200
        return f"pypi.org {r.status}"


@check("venv")
def _():
    import subprocess, venv
    venv.create("/tmp/venv", with_pip=False)
    out = subprocess.run(["/tmp/venv/bin/python", "-c", "import sys; print(sys.prefix)"], capture_output=True, text=True)
    assert out.stdout.strip() == "/tmp/venv", out
    return out.stdout.strip()


@check("pip --version")
def _():
    import subprocess
    out = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.split(" from ")[0]


if __name__ == "__main__":
    run_checks()
    ok = sum(r[1] for r in results)
    for name, good, detail in results:
        print(f"{'ok  ' if good else 'FAIL'} {name}: {detail}")
    print(f"---- {ok}/{len(results)} OK")
    sys.exit(0 if ok == len(results) else 1)
