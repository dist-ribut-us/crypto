package crypto

import (
	"crypto/rand"
	"log"
)

// RandInt returns a random int generated using crypto/rand
func RandInt(max int) int {
	var (
		bits uint = 32
		ds   uint = 32
	)
	for {
		ms := max >> bits
		if ms == 1 {
			break
		}
		if ms > 1 {
			bits += ds
		} else {
			bits -= ds
		}
		ds >>= 1
	}
	for {
		r := randInt(bits + 1)
		if r < max {
			return r
		}
	}
}

func randInt(bits uint) int {
	b := make([]byte, (bits/8)+1)
	_, err := rand.Read(b)
	randReadErr(err)
	var i int
	for ; bits > 8; bits -= 8 {
		i <<= 8
		i += int(b[0])
		b = b[1:]
	}
	i <<= uint(bits)
	var mask byte
	for ; bits > 0; bits-- {
		mask = (mask << 1) + 1
	}
	i += int(b[0] & mask)
	return i
}

// RandUint32 returns a random int generated using crypto/rand
func RandUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	randReadErr(err)
	return (uint32(b[0]) + uint32(b[1])<<8 + uint32(b[2])<<16 + uint32(b[3])<<24)
}

// RandUint16 returns a random int generated using crypto/rand
func RandUint16() uint16 {
	b := make([]byte, 2)
	_, err := rand.Read(b)
	randReadErr(err)
	return (uint16(b[0]) + uint16(b[1])<<8)
}

// InterruptHandler will be called in the case of a set of very rare errors. By
// default, the InterruptHandler will panic. Only main should change the
// InterruptHandler.
var InterruptHandler = func(err error) {
	go func() {
		// panic in goroutine so that it won't bubble and potentially be caught by
		// resolve in another package
		panic(err)
	}()
	<-make(chan bool) //block forever
}

func randReadErr(err error) bool {
	if err != nil {
		log.Print("ERROR", err)
		InterruptHandler(err)
		return true
	}
	return false
}
