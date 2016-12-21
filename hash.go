package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// DigestLength is the length of a SHA 256 hash digest
const DigestLength = 32

var WrongDigestLength = errors.New("Wrong Digest Length")

// Digest wraps the output of a hash
type Digest []byte

// SHA256 returns the sha256 Digest of a byte slice
func SHA256(b []byte) Digest {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
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
		return nil, WrongDigestLength
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
		return nil, WrongDigestLength
	}
	return Digest(b), err
}
