// Package pool provides an object pool that trades off the cost of creation
// versus retention. It is meant to avoid the pessimal behaviour (see [issue
// 23199]) seen when using a regular sync.Pool with objects of dynamic sizes;
// objects that are too large are kept alive by repeat usages that don't need
// such sizes.
//
// [issue 23199]: https://github.com/golang/go/issues/23199
package pool

import (
	"math"
	"sync/atomic"
)

// A Dynamic pool is like a sync.Pool for objects of varying sizes.
//
// It prevents the indefinite retention of (too) large objects by keeping a
// history of required object sizes (utility) and comparing them to the actual
// object size (cost) before accepting an object.
type Dynamic struct {
	Pool interface {
		Get() interface{}
		Put(interface{})
	}

	// The utility below which the cost of creating the object is more expensive
	// than just keeping it. Set this to the expected object size (or perhaps a
	// bit larger to reduce allocations more).
	MinUtility float64

	avgUtility uint64 // Actually a float64, but that type does not have atomic ops.
}

func (p *Dynamic) Get() interface{} {
	return p.Pool.Get()
}

// Put is like sync.Pool.Put, with a few differences. The utility is a measure
// of what part of the object was actually used. The cost is a measure of the
// total "size" of the object. Utility must be smaller than or equal to cost.
func (p *Dynamic) Put(v interface{}, utility, cost float64) bool {
	// Update the average utility. Uses atomic load/store, which means that
	// values can get lost if Put is called concurrently. That's fine, we're
	// just looking for an approximate (weighted) moving average.
	avgUtility := math.Float64frombits(atomic.LoadUint64(&p.avgUtility))
	avgUtility = decay(avgUtility, utility, p.MinUtility)
	atomic.StoreUint64(&p.avgUtility, math.Float64bits(avgUtility))

	if cost > 10*avgUtility {
		return false // If the cost is 10x larger than the average utility, drop it.
	}
	p.Pool.Put(v)
	return true
}

// decay updates returns `val` if `val > `prev`, otherwise it returns an
// exponentially moving average of `prev` and `val` (with factor 0.5. This is
// meant to provide a slower downramp if `val` drops ever lower. The minimum
// value is `min`.
func decay(prev, val, min float64) float64 {
	if val < min {
		val = min
	}
	if prev == 0 || val > prev {
		return val
	}
	const factor = 0.5
	return (prev * factor) + (val * (1 - factor))
}
