package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/dist-ribut-us/errors"
	"hash"
)

// DigestLength is the length of a SHA 256 hash digest
const DigestLength = 32

// ErrWrongDigestLength is returned when trying to create a digest from data
// of the wrong length
const ErrWrongDigestLength = errors.String("Wrong Digest Length")

// Digest wraps the output of a hash
type Digest [DigestLength]byte

// GetDigest returns the sha256 Digest of a byte slice
func GetDigest(bs ...[]byte) *Digest {
	h := sha256.New()
	for _, b := range bs {
		h.Write(b)
	}
	d := &Digest{}
	copy(d[:], h.Sum(nil))
	return d
}

// Hasher represents a Hash that can continue to write data
type Hasher interface {
	Write(bs ...[]byte) Hasher
	Digest() *Digest
}
type hsh struct{ hash.Hash }

// Hash returns a hasher, initilized by writing b to the hash.
func Hash(bs ...[]byte) Hasher {
	h := sha256.New()
	for _, b := range bs {
		h.Write(b)
	}
	return hsh{h}
}

// Write adds more data to the hash
func (h hsh) Write(bs ...[]byte) Hasher {
	for _, b := range bs {
		h.Hash.Write(b)
	}
	return h
}

// Digest returns the digest of the hash at it's current state
func (h hsh) Digest() *Digest {
	d := &Digest{}
	copy(d[:], h.Hash.Sum(nil))
	return d
}

// Symmetric uses a digest to create a shared key
func (d *Digest) Symmetric() *Symmetric { return (*Symmetric)(d) }

// Slice return the digest as a byte slice
func (d *Digest) Slice() []byte {
	if d == nil {
		return nil
	}
	return d[:]
}

// String returns the base64 encoding of the digest
func (d *Digest) String() string {
	if d == nil {
		return ""
	}
	return encodeToString(d[:])
}

// DigestFromSlice converts a byte slice to a public key. The values are copied,
// so the slice can be modified after.
func DigestFromSlice(bs []byte) *Digest {
	d := &Digest{}
	copy(d[:], bs)
	return d
}

// DigestFromString returns a digest from a hex string as would be returned by a
// call to String
func DigestFromString(str string) (*Digest, error) {
	b, err := decodeString(str)
	if err != nil {
		return nil, err
	}
	if len(b) != DigestLength {
		return nil, ErrWrongDigestLength
	}
	d := &Digest{}
	copy(d[:], b)
	return d, nil
}

// Equal checks if two digests are equal
func (d *Digest) Equal(other *Digest) bool {
	if d == nil || other == nil {
		return d == nil && other == nil
	}
	return *d == *other
}

// Hex returns the hexidecimal string representation of the digest
func (d *Digest) Hex() string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d[:])
}

// DigestFromHex returns a digest from a hex string as would be returned by a
// call to Hex
func DigestFromHex(hexStr string) (*Digest, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) != DigestLength {
		return nil, ErrWrongDigestLength
	}
	d := &Digest{}
	copy(d[:], b)
	return d, nil
}
