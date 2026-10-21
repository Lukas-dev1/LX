# Python networking under lx: outbound socket + DNS, and a threaded HTTP server serving parallel clients.
import http.server, socket, threading, urllib.request

s = socket.create_connection(("example.com", 80), timeout=10)
s.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
first = s.recv(64).split(b"\r\n")[0]
s.close()
print("outbound:", first.decode())

class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from {threading.current_thread().name}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

results = []
def client():
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as r:
        results.append(r.read().decode())
clients = [threading.Thread(target=client) for _ in range(20)]
for t in clients: t.start()
for t in clients: t.join()
srv.shutdown()
ok = first.startswith(b"HTTP/1.") and len(results) == 20 and all(r.startswith("hello from") for r in results)
print(f"threaded server: {len(results)}/20 responses, {threading.active_count()} threads left", "OK" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
