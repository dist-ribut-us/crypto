package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRandIntNoWrap(t *testing.T) {
	n := 1000
	// This tests that RandInt is uniform and does not have wrapping artifacts
	// around the length of an int
	maxInt := int(^uint(0) >> 1)
	half := (maxInt / 3)
	max := half * 2
	c := 0
	for i := 0; i < n; i++ {
		r := RandInt(max)
		if r > half {
			c++
		}
	}
	assert.InDelta(t, n/2, c, float64(n)/10) // should really find the correct probability here
}

func TestRandInt(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for max := maxInt; max > 0; max >>= 1 {
		r := RandInt(max)
		assert.True(t, r < max)
		assert.True(t, r >= 0)
	}
}
