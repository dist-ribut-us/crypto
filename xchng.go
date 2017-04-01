package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/dist-ribut-us/errors"
	"golang.org/x/crypto/nacl/box"
)

// KeyRef is similar to ID for private keys. It can be useful for managing
// private keys.
type KeyRef [IDLength]byte

// XchgPub Key
type XchgPub key

// XchgPriv key
type XchgPriv key

// XchgPair embeds XchgPub and XchgPriv
type XchgPair struct {
	*XchgPub
	*XchgPriv
}

// Pub is shorthand to get the XchgPub
func (pair *XchgPair) Pub() *XchgPub { return pair.XchgPub }

// Priv is shorthand to get the XchgPriv
func (pair *XchgPair) Priv() *XchgPriv { return pair.XchgPriv }

// Arr returns a reference to the array underlying the public key
func (pub *XchgPub) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(pub) }

// Arr returns a reference to the array underlying the private key
func (priv *XchgPriv) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(priv) }

// Arr returns a reference to the array underlying the KeyRef
func (keyref *KeyRef) Arr() *[IDLength]byte { return (*[IDLength]byte)(keyref) }

// XchgPubFromArr casts an array to a public key
func XchgPubFromArr(pub *[KeyLength]byte) *XchgPub { return (*XchgPub)(pub) }

// XchgPrivFromArr casts an array to a private key
func XchgPrivFromArr(priv *[KeyLength]byte) *XchgPriv { return (*XchgPriv)(priv) }

// KeyRefFromArr casts an array to a KeyRef
func KeyRefFromArr(keyref *[IDLength]byte) *KeyRef { return (*KeyRef)(keyref) }

// Slice casts the public key to a byte slice
func (pub *XchgPub) Slice() []byte { return pub[:] }

// Slice casts the private key to a byte slice
func (priv *XchgPriv) Slice() []byte { return priv[:] }

// Slice casts both keypairs to slices and appends the Pub to the end of the
// Priv.
func (pair *XchgPair) Slice() []byte {
	b := make([]byte, KeyLength*2)
	copy(b, pair.XchgPriv[:])
	copy(b[KeyLength:], pair.XchgPub[:])
	return b
}

// Slice casts the id to a byte slice
func (id *ID) Slice() []byte { return id[:] }

// String returns the base64 encoding of the public key
func (pub *XchgPub) String() string { return encodeToString(pub[:]) }

// String returns the base64 encoding of the private key
func (priv *XchgPriv) String() string { return encodeToString(priv[:]) }

func (pair *XchgPair) String() string { return encodeToString(pair.Slice()) }

// GenerateXchgPair returns a public and private key.
func GenerateXchgPair() *XchgPair {
	pub, priv, err := box.GenerateKey(rand.Reader)
	randReadErr(err)
	return &XchgPair{
		XchgPub:  (*XchgPub)(pub),
		XchgPriv: (*XchgPriv)(priv),
	}
}

// XchgPairFromString takes a two base64 encoded strings and returns a keypair
func XchgPairFromString(pairStr string) (*XchgPair, error) {
	bs, err := decodeString(pairStr)
	if err != nil {
		return nil, err
	}
	return XchgPairFromSlice(bs), nil
}

// XchgPairFromSlice takes a slice and returns an XchgPair
func XchgPairFromSlice(bs []byte) *XchgPair {
	return &XchgPair{
		XchgPriv: XchgPrivFromSlice(bs),
		XchgPub:  XchgPubFromSlice(bs[KeyLength:]),
	}
}

// XchgPubFromString takes a base64 encoded public key and returns it as a
// XchgPub
func XchgPubFromString(pubStr string) (*XchgPub, error) {
	key, err := keyFromString(pubStr)
	if err != nil {
		return nil, err
	}

	p := XchgPub(*key)
	return &p, nil
}

// XchgPrivFromString takes a base64 encoded public key and returns it as a
// XchgPriv
func XchgPrivFromString(privStr string) (*XchgPriv, error) {
	key, err := keyFromString(privStr)
	if err != nil {
		return nil, err
	}

	p := XchgPriv(*key)
	return &p, nil
}

// XchgPubFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func XchgPubFromSlice(bs []byte) *XchgPub {
	pub := XchgPub(*keyFromSlice(bs))
	return &pub
}

// XchgPrivFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func XchgPrivFromSlice(bs []byte) *XchgPriv {
	priv := XchgPriv(*keyFromSlice(bs))
	return &priv
}

// ErrIncorrectIDSize when a byte slice length does not equal IDLength
const ErrIncorrectIDSize = errors.String("Incorrect ID size")

// GetKeyRef returns the KeyRef for a private key
func (priv *XchgPriv) GetKeyRef() *KeyRef {
	h := sha256.New()
	h.Write(priv[:])
	keyRef := &KeyRef{}
	copy(keyRef[:], h.Sum(nil)[:IDLength])
	return keyRef
}

// Shared returns a Symmetric key from a public and private key
func (priv *XchgPriv) Shared(pub *XchgPub) *Symmetric {
	symmetric := &Symmetric{}
	box.Precompute(symmetric.Arr(), pub.Arr(), priv.Arr())
	return symmetric
}

// AnonSeal encrypts a message with a random key pair. The Nonce is always 0 and
// the public key is prepended to the cipher. The recipient can open the message
// but the sender remains anonymous.
func (pub *XchgPub) AnonSeal(msg []byte) []byte {
	cipher, _ := pub.AnonSealSymmetric(nil, msg)
	return cipher
}

// TagAnonSeal encrypts a message with a random key pair and prepends a byte
// slice tag. The Nonce is always 0 and the public key is prepended to the
// cipher. The recipient can open the message but the sender remains anonymous.
func (pub *XchgPub) TagAnonSeal(tag, msg []byte) []byte {
	cipher, _ := pub.AnonSealSymmetric(tag, msg)
	return cipher
}

// AnonOpen decrypts a cipher from AnonSeal or AnonSealSymmetric.
func (priv *XchgPriv) AnonOpen(cipher []byte) ([]byte, error) {
	msg, _, err := priv.AnonOpenSymmetric(cipher)
	return msg, err
}

// AnonSealSymmetric encrypts a message with a random key pair. The Nonce is always
// 0 and the public key is prepended to the cipher. The recipient can open the
// message but the sender remains anonymous. This method also returns the symmetric
// key for the message.
func (pub *XchgPub) AnonSealSymmetric(tag, msg []byte) ([]byte, *Symmetric) {
	otk := GenerateXchgPair()
	symmetric := otk.Shared(pub)
	l := len(tag)
	bts := make([]byte, l+KeyLength, box.Overhead+l+len(msg))
	copy(bts, tag)
	copy(bts[l:], otk.XchgPub[:])
	return box.SealAfterPrecomputation(bts, msg, zeroNonce.Arr(), symmetric.Arr()), symmetric
}

// AnonOpenSymmetric decrypts a cipher from AnonSeal or AnonSealSymmetric and returns
// the symmetric key.
func (priv *XchgPriv) AnonOpenSymmetric(cipher []byte) ([]byte, *Symmetric, error) {
	if len(cipher) <= KeyLength {
		return nil, nil, ErrDecryptionFailed
	}
	otkXchgPub := &XchgPub{}
	copy(otkXchgPub[:], cipher[:KeyLength])
	symmetric := priv.Shared(otkXchgPub)

	msg, ok := box.OpenAfterPrecomputation(nil, cipher[KeyLength:], zeroNonce.Arr(), symmetric.Arr())
	if !ok {
		return nil, nil, ErrDecryptionFailed
	}
	return msg, symmetric, nil
}
