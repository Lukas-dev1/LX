# Short timed waits sleep about as long as asked: neither return at once (a busy loop) nor take NT's
# 15.6 ms tick.
import select, threading, time
c = threading.Condition()
with c:
    t = time.perf_counter()
    for _ in range(100):
        c.wait(0.001)
    cond = (time.perf_counter() - t) * 1000
t = time.perf_counter()
for _ in range(100):
    select.select([], [], [], 0.0005)
sel = (time.perf_counter() - t) * 1000
assert 90 <= cond <= 800, f"100 x 1 ms condition waits took {cond:.0f} ms"
assert 45 <= sel <= 800, f"100 x 0.5 ms selects took {sel:.0f} ms"
print("OK")
