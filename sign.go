package crypto

import (
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

// SignPub is a public key used to verify signatures
type SignPub key

// SignPrivLength is the length of a private signature key
const SignPrivLength = 64

// SignPriv is a private key used to sign messages
type SignPriv [SignPrivLength]byte

// SignatureLength is the correct length of a signature
const SignatureLength = 64

// String returns the base64 encoding of the private key
func (priv *SignPriv) String() string { return encodeToString(priv[:]) }

// String returns the base64 encoding of the public key
func (pub *SignPub) String() string { return encodeToString(pub[:]) }

// Slice casts the public key to a byte slice
func (pub *SignPub) Slice() []byte { return pub[:] }

// SignPubFromString takes a base64 encoded public key and returns it as a
// SignPub
func SignPubFromString(pubStr string) (*SignPub, error) {
	key, err := keyFromString(pubStr)
	if err != nil {
		return nil, err
	}

	p := SignPub(*key)
	return &p, nil
}

// SignPubFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func SignPubFromSlice(bs []byte) *SignPub {
	pub := SignPub(*keyFromSlice(bs))
	return &pub
}

// Signature produced from signing a message
type Signature []byte

// GenerateSignPair creates a pair of signing keys.
func GenerateSignPair() (*SignPub, *SignPriv) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	randReadErr(err)
	sigPub, sigPriv := &SignPub{}, &SignPriv{}
	copy(sigPub[:], pub)
	copy(sigPriv[:], priv)
	return sigPub, sigPriv
}

// Sign returns a 64 byte Signature
func (priv *SignPriv) Sign(msg []byte) Signature {
	return ed25519.Sign(priv[:], msg)
}

// Verify that a the matching private key was used to sign a message
func (pub *SignPub) Verify(msg []byte, signature Signature) bool {
	return ed25519.Verify(pub[:], msg, signature)
}

// Pub gets the public key from a private key.
func (priv *SignPriv) Pub() *SignPub {
	pub := &SignPub{}
	copy(pub[:], priv[KeyLength:])
	return pub
}

// ID is a shorthand used to make referencing public keys easier. An ID is the
// first 10 bytes of the sha256 of a public key. While the chances of accidental
// collision should be minimal, malicious collision should not be discounted. ID
// can be used as to make hash tables more efficient, but should not be
// substituted for a full key check.
type ID [IDLength]byte

// Arr returns a reference to the array underlying the ID
func (id *ID) Arr() *[IDLength]byte { return (*[IDLength]byte)(id) }

// IDFromArr casts an array to an ID
func IDFromArr(id *[IDLength]byte) *ID { return (*ID)(id) }

// String returns the base64 encoding of the id
func (id *ID) String() string { return encodeToString(id[:]) }

// ID returns the ID for a public key.
func (pub *SignPub) ID() *ID {
	id := &ID{}
	copy(id[:], Hash(pub[:]).Digest()[:])
	return id
}

// IDFromSlice returns an ID from a byte slice. The values are copied, so the
// slice can be modified after
func IDFromSlice(b []byte) (*ID, error) {
	if len(b) != IDLength {
		return nil, ErrIncorrectIDSize
	}
	id := &ID{}
	copy(id[:], b)
	return id, nil
}

// IDFromString takes a base64 encoded ID key and returns it as *ID
func IDFromString(str string) (*ID, error) {
	id := &ID{}

	data, err := decodeString(str)
	if err != nil {
		return nil, err
	}
	copy(id[:], data)

	return id, nil
}
