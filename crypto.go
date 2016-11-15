package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/nacl/box"
)

const KeyLength = 32
const NonceLength = 24
const IDLength = 10
const TagLength = 16

// ID is a shorthand used to make referencing public keys easier. An ID is the
// first 10 bytes of the sha256 of a public key. While the chances of accidental
// collision should be minimal, malicious collision should not be discounted. ID
// can be used as to make hash tables more efficient, but should not be
// substituded for a full key check.
type ID [IDLength]byte
type KeyRef [IDLength]byte
type Nonce [NonceLength]byte
type key [KeyLength]byte
type Pub key
type Priv key
type Shared key

func (pub *Pub) Arr() *[KeyLength]byte       { return (*[KeyLength]byte)(pub) }
func (priv *Priv) Arr() *[KeyLength]byte     { return (*[KeyLength]byte)(priv) }
func (shared *Shared) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(shared) }
func (id *ID) Arr() *[IDLength]byte          { return (*[IDLength]byte)(id) }
func (keyref *KeyRef) Arr() *[IDLength]byte  { return (*[IDLength]byte)(keyref) }
func (noncd *Nonce) Arr() *[NonceLength]byte { return (*[NonceLength]byte)(noncd) }
func (key *key) Arr() *[KeyLength]byte       { return (*[KeyLength]byte)(key) }

func PubFromArr(pub *[KeyLength]byte) *Pub          { return (*Pub)(pub) }
func PrivFromArr(priv *[KeyLength]byte) *Priv       { return (*Priv)(priv) }
func SharedFromArr(shared *[KeyLength]byte) *Shared { return (*Shared)(shared) }
func IDFromArr(id *[IDLength]byte) *ID              { return (*ID)(id) }
func KeyRefFromArr(keyref *[IDLength]byte) *KeyRef  { return (*KeyRef)(keyref) }
func NonceFromArr(noncd *[NonceLength]byte) *Nonce  { return (*Nonce)(noncd) }
func keyFromArr(k *[KeyLength]byte) *key            { return (*key)(k) }

func (pub *Pub) Slice() []byte { return pub[:] }

func (p *Pub) String() string    { return base64.StdEncoding.EncodeToString(p[:]) }
func (p *Priv) String() string   { return base64.StdEncoding.EncodeToString(p[:]) }
func (s *Shared) String() string { return base64.StdEncoding.EncodeToString(s[:]) }
func (i *ID) String() string     { return base64.StdEncoding.EncodeToString(i[:]) }

func GenerateKey() (*Pub, *Priv, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return PubFromArr(pub), PrivFromArr(priv), nil
}

// KeyPairFromString takes a two base64 encoded strings and returns a keypair
func KeyPairFromString(pubStr, privStr string) (*Pub, *Priv, error) {
	pub := &Pub{}
	priv := &Priv{}

	data, err := base64.StdEncoding.DecodeString(pubStr)
	if err != nil {
		return nil, nil, err
	}
	copy(pub[:], data)

	data, err = base64.StdEncoding.DecodeString(privStr)
	if err != nil {
		return nil, nil, err
	}
	copy(priv[:], data)

	return pub, priv, nil
}

// PubFromString takes a base64 encoded public key and returns it as a Pub
func PubFromString(pubStr string) (*Pub, error) {
	pub := &Pub{}

	data, err := base64.StdEncoding.DecodeString(pubStr)
	if err != nil {
		return nil, err
	}
	copy(pub[:], data)

	return pub, nil
}

// GetID returns the ID for a public key.
func (pub Pub) GetID() *ID {
	h := sha256.New()
	h.Write(pub[:])
	id := &ID{}
	copy(id[:], h.Sum(nil)[:IDLength])
	return id
}

var IncorrectIDSize = errors.New("Incorrect ID size")

func IDFromSlice(b []byte) (*ID, error) {
	if len(b) != IDLength {
		return nil, IncorrectIDSize
	}
	id := &ID{}
	copy(id[:], b)
	return id, nil
}

func (priv Priv) GetKeyRef() *KeyRef {
	h := sha256.New()
	h.Write(priv[:])
	keyRef := &KeyRef{}
	copy(keyRef[:], h.Sum(nil)[:IDLength])
	return keyRef
}

var IncorrectPubKeySize = errors.New("Incorrect Public key size")

func PubFromSlice(b []byte) (*Pub, error) {
	if len(b) != KeyLength {
		return nil, IncorrectPubKeySize
	}
	pub := &Pub{}
	copy(pub[:], b)
	return pub, nil
}

func (pub *Pub) Precompute(priv *Priv) *Shared {
	shared := &Shared{}
	box.Precompute(shared.Arr(), pub.Arr(), priv.Arr())
	return shared
}

func (shared *Shared) Seal(msg []byte) []byte {
	out := make([]byte, NonceLength, len(msg)+TagLength+NonceLength)
	nonce := &Nonce{}
	rand.Read(nonce[:])
	copy(out, nonce[:])

	return box.SealAfterPrecomputation(out, msg, nonce.Arr(), shared.Arr())
}

func (shared *Shared) SealAll(msgs [][]byte) [][]byte {
	ciphers := make([][]byte, len(msgs))
	for i, msg := range msgs {
		ciphers[i] = shared.Seal(msg)
	}
	return ciphers
}

var DecryptionFailed = errors.New("Decryption Failed")

func (shared *Shared) Open(cipher []byte) ([]byte, error) {
	nonce := &Nonce{}
	copy(nonce[:], cipher[:NonceLength])

	data, ok := box.OpenAfterPrecomputation(nil, cipher[NonceLength:], nonce.Arr(), shared.Arr())
	if !ok {
		return nil, DecryptionFailed
	}

	return data, nil
}

var zeroNonce = &Nonce{}

func (pub *Pub) AnonSeal(msg []byte) ([]byte, error) {
	cipher, _, err := pub.AnonSealShared(msg)
	return cipher, err
}

func (priv *Priv) AnonOpen(cipher []byte) ([]byte, error) {
	msg, _, err := priv.AnonOpenShared(cipher)
	return msg, err
}

func (pub *Pub) AnonSealShared(msg []byte) ([]byte, *Shared, error) {
	otkPub, otkPriv, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	shared := pub.Precompute(otkPriv)
	return box.SealAfterPrecomputation(otkPub[:], msg, zeroNonce.Arr(), shared.Arr()), shared, nil
}

func (priv *Priv) AnonOpenShared(cipher []byte) ([]byte, *Shared, error) {
	if len(cipher) <= KeyLength {
		return nil, nil, DecryptionFailed
	}
	otkPub := &Pub{}
	copy(otkPub[:], cipher[:KeyLength])
	shared := otkPub.Precompute(priv)

	msg, ok := box.OpenAfterPrecomputation(nil, cipher[KeyLength:], zeroNonce.Arr(), shared.Arr())
	if !ok {
		return nil, nil, DecryptionFailed
	}
	return msg, shared, nil
}

func (n *Nonce) Inc() *Nonce {
	for i, v := range n {
		n[i]++
		if v != 255 {
			break
		}
	}
	return n
}

/*
This is no good, because of the way it will wrap, some numbers will have twice the chance
*/
func RandInt(max int) int {
	b := make([]byte, 4)
	rand.Read(b)
	return (int(b[0]) + int(b[1])<<8 + int(b[2])<<16 + int(b[3])<<24) % max
}

func RandUint32() uint32 {
	b := make([]byte, 4)
	rand.Read(b)
	return (uint32(b[0]) + uint32(b[1])<<8 + uint32(b[2])<<16 + uint32(b[3])<<24)
}
