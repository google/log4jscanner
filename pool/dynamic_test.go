package pool

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

const bufSize = 4096

// The desired behaviour of the dynamic (buffer) pool is:
//   - Don't retain (very) large items indefinitely (check that one is rejected
//     at least once).
//   - Do retain even large items for a while so their allocation cost is
//     amortized.
func TestDynamic(t *testing.T) {
	dp := Dynamic{
		Pool:       sync.Pool{New: func() interface{} { return make([]byte, 0) }},
		MinUtility: bufSize,
	}
	var allocs int
	// Simulate a sequence of file sizes. This sequence is not based on some
	// real-life observed sequence of sizes of jar-in-jars. It might be better
	// to use such a sequence, but every organisation will have its own expected
	// sizes and this synthetic one conains some fairly extreme samples that
	// check whether the algorithm is robust.
	//
	// For the current algorithm, the worst possible sequence is one that
	// rises, then suddenly drops and then rises slowly again. We contend that
	// this case is rare.
	sizes := [...]int{
		100000, 1, 1, 1, 1, 1, 10, 1, 1, 1, 1, 1, 1, 1, 12, 1, 1, 1, 1, 1, 1, 1,
		1000, 100, 10000, 100000, 1, 100000, 1, 50000, 1, 1, 25000, 1, 1, 1,
		100000, 1, 1, 1, 1, 1, 1, 1, 1, 1, 100, 100, 100, 1, 1, 1, 1, 1, 100,
		200, 300, 100, 50, 50, 50, 50, 50, 1, 1, 1, 1, 100000000, 1000000,
		100000, 10000, 1000, 100, 10, 1, 1, 500, 2020, 400, 3984, 5, 200, 500,
		40000, 35000, 45000, 42000, 38000, 38000, 39000, 41000, 42000, 42000, // Average: 40000
		2000, 4000, 3949, 2011, 4096, 33, 0, 4938, 1, 1, 1200, 2400, 1200, 200,
		400, 600, 700, 100, 400, 500, 700, 600, 900, 1000, 1100, 1200, 1000,
	}

	var largeBufferPurged int

	t.Logf("num allocs value target capacity")
	// This test assumes (with some margin for error) that back-to-back Put/Get
	// on a pool from a single goroutine yield the same item. I believe this to
	// be a fairly stable assumption avoiding plenty of testing boilerplate,
	// time will tell.
	for idx, size := range sizes {
		buf := dp.Get().([]byte)
		if cap(buf) < size {
			capacity := size
			if capacity < bufSize {
				capacity = bufSize // Allocating much smaller buffers could lead to quick re-allocations.
			}
			buf = make([]byte, size, capacity)
			allocs++
		} else {
			buf = buf[:size]
		}
		utility := float64(len(buf))
		if utility < bufSize {
			utility = bufSize
		}
		if !dp.Put(buf, utility, float64(cap(buf))) && cap(buf) >= 100000 {
			largeBufferPurged++
		}
		avgUtility := math.Float64frombits(atomic.LoadUint64(&dp.avgUtility))
		t.Logf("%d %d %d %f %d", idx+1, allocs, size, avgUtility, cap(buf))
	}
	// Before the amortized buffer optimization, each iteration would've been
	// one allocation. We want at least 10x fewer than that.
	if got, want := allocs, len(sizes)/10; got > want {
		t.Errorf("got %d allocations, wanted %d", got, want)
	}
	if got, atLeast := largeBufferPurged, 2; got < atLeast {
		t.Errorf("buffers >= 100000 have been rejected %d times, expected at least %d", got, atLeast)
	}
}
