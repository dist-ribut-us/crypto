package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
)

// DigestLength is the length of a SHA 256 hash digest
const DigestLength = 32

// ErrWrongDigestLength is returned when trying to create a digest from data
// of the wrong length
var ErrWrongDigestLength = errors.New("Wrong Digest Length")

// Digest wraps the output of a hash
type Digest []byte

// GetDigest returns the sha256 Digest of a byte slice
func GetDigest(bs ...[]byte) Digest {
	h := sha256.New()
	for _, b := range bs {
		h.Write(b)
	}
	return h.Sum(nil)
}

// Hasher represents a Hash that can continue to write data
type Hasher interface {
	Write(bs ...[]byte) Hasher
	Digest() Digest
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
func (h hsh) Digest() Digest { return h.Hash.Sum(nil) }

// Shared uses a digest to create a shared key
func (d Digest) Shared() *Shared {
	var sh Shared
	copy(sh[:], d)
	return &sh
}

// String returns the base64 encoding of the digest
func (d Digest) String() string { return base64.StdEncoding.EncodeToString(d) }

// DigestFromString returns a digest from a hex string as would be returned by a
// call to String
func DigestFromString(str string) (Digest, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	if len(b) != DigestLength {
		return nil, ErrWrongDigestLength
	}
	return Digest(b), err
}

// Equal checks if two digests are equal
func (d Digest) Equal(other Digest) bool { return bytes.Equal(d, other) }

// Hex returns the hexidecimal string representation of the digest
func (d Digest) Hex() string { return hex.EncodeToString(d) }

// DigestFromHex returns a digest from a hex string as would be returned by a
// call to Hex
func DigestFromHex(hexStr string) (Digest, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	if len(b) != DigestLength {
		return nil, ErrWrongDigestLength
	}
	return Digest(b), err
}
