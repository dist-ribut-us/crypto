package crypto

import (
	"crypto/rand"
	"github.com/dist-ribut-us/errors"
	"golang.org/x/crypto/nacl/box"
)

// Symmetric key. Symmetric keys are also used as symmetric keys.
type Symmetric key

// Arr returns a reference to the array underlying the symmetric key
func (symmetric *Symmetric) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(symmetric) }

// SymmetricFromArr casts an array to a symmetric key
func SymmetricFromArr(symmetric *[KeyLength]byte) *Symmetric { return (*Symmetric)(symmetric) }

// Slice casts the public key to a byte slice
func (symmetric *Symmetric) Slice() []byte { return symmetric[:] }

// String returns the base64 encoding of the symmetric key
func (symmetric *Symmetric) String() string { return encodeToString(symmetric[:]) }

// RandomSymmetric returns a random symmetric key that can be used for symmetric
// ciphers
func RandomSymmetric() *Symmetric {
	b := make([]byte, KeyLength)
	_, err := rand.Read(b)
	if randReadErr(err) {
		return nil
	}

	s := &Symmetric{}
	copy(s[:], b)
	return s
}

// SymmetricFromString takes a base64 encoded public key and returns it as a Symmetric
func SymmetricFromString(symmetricStr string) (*Symmetric, error) {
	key, err := keyFromString(symmetricStr)
	if err != nil {
		return nil, err
	}

	s := Symmetric(*key)
	return &s, nil
}

// SymmetricFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func SymmetricFromSlice(bs []byte) *Symmetric {
	symmetric := Symmetric(*keyFromSlice(bs))
	return &symmetric
}

// Seal will seal message using a symmetric key and the given nonce. If the nonce
// is nil, a random nonce is generated. Decyrpted with Open
func (symmetric *Symmetric) Seal(msg []byte, nonce *Nonce) []byte {
	out := make([]byte, NonceLength, len(msg)+box.Overhead+NonceLength)
	if nonce == nil {
		nonce = RandomNonce()
	}
	copy(out, nonce[:])

	return box.SealAfterPrecomputation(out, msg, nonce.Arr(), symmetric.Arr())
}

// SealAll seals many messages with the same shared key. If nonce is nil, a
// random nonce will be generated for each message.
func (symmetric *Symmetric) SealAll(msgs [][]byte, nonce *Nonce) [][]byte {
	return symmetric.SealPackets(nil, msgs, nonce, 0)
}

// SealPackets will seal message using a symmetric key and the given nonce. If the
// nonce is nil, a random nonce is generated. The tag will be prepended, but
// not encrypted. Trim removes tags from the start of each packet.
func (symmetric *Symmetric) SealPackets(tag []byte, msgs [][]byte, nonce *Nonce, trim int) [][]byte {
	tl := len(tag)
	pkts := make([][]byte, len(msgs))
	if nonce == nil {
		nonce = RandomNonce()
	}
	ln, cp := tl+NonceLength, tl+NonceLength+box.Overhead
	for i, msg := range msgs {
		pkt := make([]byte, ln, cp+len(msg)-trim)
		copy(pkt, tag)
		copy(pkt[tl:], nonce[:])
		pkts[i] = box.SealAfterPrecomputation(pkt, msg[trim:], nonce.Arr(), symmetric.Arr())
		nonce.Inc()
	}

	return pkts
}

// ErrDecryptionFailed when no other information is available
const ErrDecryptionFailed = errors.String("Decryption Failed")

// Open will decipher a message ciphered with Seal.
func (symmetric *Symmetric) Open(cipher []byte) ([]byte, error) {
	if cipher == nil {
		return nil, nil
	}
	nonce := &Nonce{}
	if len(cipher) < NonceLength {
		return nil, ErrDecryptionFailed
	}
	copy(nonce[:], cipher[:NonceLength])

	data, ok := box.OpenAfterPrecomputation(nil, cipher[NonceLength:], nonce.Arr(), symmetric.Arr())
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return data, nil
}

// NonceOpen will decipher a message with a specific nonce
func (symmetric *Symmetric) NonceOpen(cipher []byte, nonce *Nonce) ([]byte, error) {
	if cipher == nil {
		return nil, nil
	}
	if nonce == nil {
		nonce = zeroNonce
	}
	data, ok := box.OpenAfterPrecomputation(nil, cipher, nonce.Arr(), symmetric.Arr())
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return data, nil
}
