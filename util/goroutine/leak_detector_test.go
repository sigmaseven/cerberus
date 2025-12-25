package goroutine

import (
	"sync"
	"testing"
	"time"
)

func TestAssertNoLeaks_NoLeak(t *testing.T) {
	AssertNoLeaks(t)

	// Launch goroutine that completes quickly
	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(done)
	}()
	<-done
}

func TestAssertNoLeaks_WithWaitGroup(t *testing.T) {
	AssertNoLeaks(t)

	var wg sync.WaitGroup
	wg.Add(3)

	for i := 0; i < 3; i++ {
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
		}()
	}

	wg.Wait()
}

func TestGoroutineSnapshot_Compare(t *testing.T) {
	snapshot := TakeSnapshot()

	// Launch a goroutine
	done := make(chan struct{})
	go func() {
		<-done
	}()

	// Goroutine count should be higher
	diff := snapshot.Compare()
	if diff < 1 {
		t.Errorf("expected positive difference after launching goroutine, got %d", diff)
	}

	// Clean up
	close(done)
	time.Sleep(50 * time.Millisecond)

	// Should be back to baseline or close to it
	diff = snapshot.Compare()
	if diff > 0 {
		t.Logf("note: still %d extra goroutines (may be from runtime)", diff)
	}
}

func TestGoroutineSnapshot_AssertNoLeak(t *testing.T) {
	snapshot := TakeSnapshot()

	// Launch a goroutine that cleans up
	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(done)
	}()

	<-done
	snapshot.AssertNoLeak(t, 5*time.Second)
}

func TestWaitForGoroutineCount_Success(t *testing.T) {
	target := GetGoroutineCount()

	// Launch temporary goroutine
	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(done)
	}()

	<-done

	// Should return true when goroutine count returns to target
	if !WaitForGoroutineCount(target+1, time.Second, 10*time.Millisecond) {
		t.Error("expected WaitForGoroutineCount to succeed")
	}
}

func TestGetGoroutineCount(t *testing.T) {
	count := GetGoroutineCount()
	if count < 1 {
		t.Errorf("expected at least 1 goroutine, got %d", count)
	}
}
