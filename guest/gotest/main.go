// Go runtime under lx: OS threads, goroutines, channels, mutexes, timers, GC. Prints OK/FAIL, exits 0/1.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	ok := true
	fail := func(f string, a ...any) { fmt.Printf("FAIL: "+f+"\n", a...); ok = false }

	// Parallel CPU work across GOMAXPROCS threads.
	const workers, n = 16, 2_000_000
	results := make(chan int, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			s := 0
			for i := 0; i < n; i++ {
				s += i % (w + 1)
			}
			results <- s
		}(w)
	}
	total := 0
	for w := 0; w < workers; w++ {
		total += <-results
	}
	want := 0
	for w := 0; w < workers; w++ {
		for i := 0; i < n; i++ {
			want += i % (w + 1)
		}
	}
	if total != want {
		fail("parallel sum %d, want %d", total, want)
	}

	// Contended mutex + WaitGroup.
	var mu sync.Mutex
	var wg sync.WaitGroup
	counter := 0
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10_000; i++ {
				mu.Lock()
				counter++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if counter != 640_000 {
		fail("counter %d", counter)
	}

	// Timers: sleep, timeout via select.
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	if d := time.Since(start); d < 90*time.Millisecond || d > 2*time.Second {
		fail("sleep took %v", d)
	}
	select {
	case <-make(chan int):
		fail("received from a dead channel")
	case <-time.After(50 * time.Millisecond):
	}

	// GC under allocation pressure.
	var keep [][]byte
	for i := 0; i < 2000; i++ {
		b := make([]byte, 64<<10)
		b[0] = byte(i)
		if i%100 == 0 {
			keep = append(keep, b)
		}
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if len(keep) != 20 || ms.NumGC == 0 {
		fail("gc: kept %d, NumGC %d", len(keep), ms.NumGC)
	}

	status := "OK"
	if !ok {
		status = "FAIL"
	}
	fmt.Printf("go %s, GOMAXPROCS=%d, threads ok, sum=%d, counter=%d, gc=%d, pid=%d %s\n",
		runtime.Version(), runtime.GOMAXPROCS(0), total, counter, ms.NumGC, os.Getpid(), status)
	if !ok {
		os.Exit(1)
	}
}
