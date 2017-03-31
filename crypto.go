package crypto

import (
	"encoding/base64"
	"golang.org/x/crypto/nacl/box"
)

// Use URL encoding standard so / doesn't give us trouble
var encodeToString = base64.URLEncoding.EncodeToString
var decodeString = base64.URLEncoding.DecodeString

// IDLength of array
const IDLength = 10

// Overhead copies box.Overhead
const Overhead = box.Overhead

// KeyLength of array applies to XchgPublic, XchgPrivate and Symmetric keys.
const KeyLength = 32

type key [KeyLength]byte

func (key *key) arr() *[KeyLength]byte { return (*[KeyLength]byte)(key) }

func keyFromArr(k *[KeyLength]byte) *key { return (*key)(k) }

func keyFromString(str string) (*key, error) {
	key := &key{}

	data, err := decodeString(str)
	if err != nil {
		return nil, err
	}
	copy(key[:], data)

	return key, nil
}

func keyFromSlice(bs []byte) *key {
	key := &key{}
	copy(key[:], bs)
	return key
}
