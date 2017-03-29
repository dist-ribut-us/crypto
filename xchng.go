package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/dist-ribut-us/errors"
	"golang.org/x/crypto/nacl/box"
)

// IDLength of array
const IDLength = 10

// ID is a shorthand used to make referencing public keys easier. An ID is the
// first 10 bytes of the sha256 of a public key. While the chances of accidental
// collision should be minimal, malicious collision should not be discounted. ID
// can be used as to make hash tables more efficient, but should not be
// substituted for a full key check.
type ID [IDLength]byte

// KeyRef is similar to ID for private keys. It can be useful for managing
// private keys.
type KeyRef [IDLength]byte

// XchgPub Key
type XchgPub key

// XchgPriv key
type XchgPriv key

// Arr returns a reference to the array underlying the public key
func (pub *XchgPub) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(pub) }

// Arr returns a reference to the array underlying the private key
func (priv *XchgPriv) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(priv) }

// Arr returns a reference to the array underlying the ID
func (id *ID) Arr() *[IDLength]byte { return (*[IDLength]byte)(id) }

// Arr returns a reference to the array underlying the KeyRef
func (keyref *KeyRef) Arr() *[IDLength]byte { return (*[IDLength]byte)(keyref) }

// XchgPubFromArr casts an array to a public key
func XchgPubFromArr(pub *[KeyLength]byte) *XchgPub { return (*XchgPub)(pub) }

// XchgPrivFromArr casts an array to a private key
func XchgPrivFromArr(priv *[KeyLength]byte) *XchgPriv { return (*XchgPriv)(priv) }

// IDFromArr casts an array to an ID
func IDFromArr(id *[IDLength]byte) *ID { return (*ID)(id) }

// KeyRefFromArr casts an array to a KeyRef
func KeyRefFromArr(keyref *[IDLength]byte) *KeyRef { return (*KeyRef)(keyref) }

// Slice casts the public key to a byte slice
func (pub *XchgPub) Slice() []byte { return pub[:] }

// Slice casts the private key to a byte slice
func (priv *XchgPriv) Slice() []byte { return priv[:] }

// Slice casts the id to a byte slice
func (id *ID) Slice() []byte { return id[:] }

// String returns the base64 encoding of the public key
func (pub *XchgPub) String() string { return encodeToString(pub[:]) }

// String returns the base64 encoding of the private key
func (priv *XchgPriv) String() string { return encodeToString(priv[:]) }

// String returns the base64 encoding of the id
func (id *ID) String() string { return encodeToString(id[:]) }

// GenerateXchgKeypair returns a public and private key.
func GenerateXchgKeypair() (*XchgPub, *XchgPriv) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	randReadErr(err)
	return (*XchgPub)(pub), (*XchgPriv)(priv)
}

// KeyPairFromString takes a two base64 encoded strings and returns a keypair
func KeyPairFromString(pubStr, privStr string) (*XchgPub, *XchgPriv, error) {
	pub, err := XchgPubFromString(pubStr)
	if err != nil {
		return nil, nil, err
	}
	priv, err := XchgPrivFromString(privStr)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// XchgPubFromString takes a base64 encoded public key and returns it as a XchgPub
func XchgPubFromString(pubStr string) (*XchgPub, error) {
	key, err := keyFromString(pubStr)
	if err != nil {
		return nil, err
	}

	p := XchgPub(*key)
	return &p, nil
}

// XchgPrivFromString takes a base64 encoded public key and returns it as a XchgPriv
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

// GetID returns the ID for a public key.
func (pub *XchgPub) GetID() *ID {
	id := &ID{}
	copy(id[:], Hash(pub[:]).Digest()[:])
	return id
}

// ErrIncorrectIDSize when a byte slice length does not equal IDLength
const ErrIncorrectIDSize = errors.String("Incorrect ID size")

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

// GetKeyRef returns the KeyRef for a private key
func (priv *XchgPriv) GetKeyRef() *KeyRef {
	h := sha256.New()
	h.Write(priv[:])
	keyRef := &KeyRef{}
	copy(keyRef[:], h.Sum(nil)[:IDLength])
	return keyRef
}

// Shared returns a Symmetric key from a public and private key
func (pub *XchgPub) Shared(priv *XchgPriv) *Symmetric {
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
	otkXchgPub, otkXchgPriv := GenerateXchgKeypair()
	symmetric := pub.Shared(otkXchgPriv)
	l := len(tag)
	bts := make([]byte, l+KeyLength, box.Overhead+l+len(msg))
	copy(bts, tag)
	copy(bts[l:], otkXchgPub[:])
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
	symmetric := otkXchgPub.Shared(priv)

	msg, ok := box.OpenAfterPrecomputation(nil, cipher[KeyLength:], zeroNonce.Arr(), symmetric.Arr())
	if !ok {
		return nil, nil, ErrDecryptionFailed
	}
	return msg, symmetric, nil
}
