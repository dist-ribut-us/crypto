package crypto

import (
	"crypto/rand"
)

// NonceLength of array
const NonceLength = 24

// Nonce array
type Nonce [NonceLength]byte

var zeroNonce = &Nonce{}

// Arr returns a reference to the array underlying the Nonce
func (nonce *Nonce) Arr() *[NonceLength]byte { return (*[NonceLength]byte)(nonce) }

// NonceFromArr casts an array to a Nonce
func NonceFromArr(nonce *[NonceLength]byte) *Nonce { return (*Nonce)(nonce) }

// NonceFromSlice casts an array to a Nonce
func NonceFromSlice(nonceSlice []byte) *Nonce {
	var nonce Nonce
	copy(nonce[:], nonceSlice)
	return &nonce
}

// Slice casts the nonce to a byte slice
func (nonce *Nonce) Slice() []byte { return nonce[:] }

// String returns the base64 encoding of the nonce
func (nonce *Nonce) String() string { return encodeToString(nonce[:]) }

// NonceFromString takes a base64 encoded nonce and returns it as a Nonce
func NonceFromString(nonceStr string) (*Nonce, error) {
	nonce := &Nonce{}

	data, err := decodeString(nonceStr)
	if err != nil {
		return nil, err
	}
	copy(nonce[:], data)

	return nonce, nil
}

// RandomNonce returns a Nonce with a cryptographically random value.
func RandomNonce() *Nonce {
	nonce := &Nonce{}
	_, err := rand.Read(nonce[:])
	if randReadErr(err) {
		return nil
	}
	return nonce
}

// Inc increments the Nonce
func (nonce *Nonce) Inc() *Nonce {
	for i, v := range nonce {
		nonce[i]++
		if v != 255 {
			break
		}
	}
	return nonce
}
