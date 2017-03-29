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

// Signature produced from signing a message
type Signature []byte

// GenerateSignKeypair creates a pair of signing keys.
func GenerateSignKeypair() (*SignPub, *SignPriv) {
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
