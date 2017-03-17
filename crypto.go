package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/dist-ribut-us/errors"
	"golang.org/x/crypto/nacl/box"
	"log"
)

// InterruptHandler will be called in the case of a set of very rare errors. By
// default, the InterruptHandler will panic. Only main should change the
// InterruptHandler.
var InterruptHandler = func(err error) {
	go func() {
		// panic in goroutine so that it won't bubble and potentially be caught by
		// resolve in another package
		panic(err)
	}()
	make(chan bool) <- false //block forever
}

func randReadErr(err error) bool {
	if err != nil {
		log.Print(err)
		InterruptHandler(err)
		return true
	}
	return false
}

// Use URL encoding standard so / doesn't give us trouble
var encodeToString = base64.URLEncoding.EncodeToString
var decodeString = base64.URLEncoding.DecodeString

// Overhead copies box.Overhead
const Overhead = box.Overhead

// KeyLength of array applies to Public, Private and Shared keys.
const KeyLength = 32

// NonceLength of array
const NonceLength = 24

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

// Nonce array
type Nonce [NonceLength]byte

type key [KeyLength]byte

// Pub Key
type Pub key

// Priv key
type Priv key

// Shared key. Shared keys are also used as symmetric keys.
type Shared key

// Arr returns a reference to the array underlying the public key
func (pub *Pub) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(pub) }

// Arr returns a reference to the array underlying the private key
func (priv *Priv) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(priv) }

// Arr returns a reference to the array underlying the shared key
func (shared *Shared) Arr() *[KeyLength]byte { return (*[KeyLength]byte)(shared) }

// Arr returns a reference to the array underlying the ID
func (id *ID) Arr() *[IDLength]byte { return (*[IDLength]byte)(id) }

// Arr returns a reference to the array underlying the KeyRef
func (keyref *KeyRef) Arr() *[IDLength]byte { return (*[IDLength]byte)(keyref) }

// Arr returns a reference to the array underlying the Nonce
func (nonce *Nonce) Arr() *[NonceLength]byte { return (*[NonceLength]byte)(nonce) }

func (key *key) arr() *[KeyLength]byte { return (*[KeyLength]byte)(key) }

// PubFromArr casts an array to a public key
func PubFromArr(pub *[KeyLength]byte) *Pub { return (*Pub)(pub) }

// PrivFromArr casts an array to a private key
func PrivFromArr(priv *[KeyLength]byte) *Priv { return (*Priv)(priv) }

// SharedFromArr casts an array to a shared key
func SharedFromArr(shared *[KeyLength]byte) *Shared { return (*Shared)(shared) }

// IDFromArr casts an array to an ID
func IDFromArr(id *[IDLength]byte) *ID { return (*ID)(id) }

// KeyRefFromArr casts an array to a KeyRef
func KeyRefFromArr(keyref *[IDLength]byte) *KeyRef { return (*KeyRef)(keyref) }

// NonceFromArr casts an array to a Nonce
func NonceFromArr(noncd *[NonceLength]byte) *Nonce { return (*Nonce)(noncd) }

func keyFromArr(k *[KeyLength]byte) *key { return (*key)(k) }

// Slice casts the public key to a byte slice
func (pub *Pub) Slice() []byte { return pub[:] }

// Slice casts the private key to a byte slice
func (priv *Priv) Slice() []byte { return priv[:] }

// Slice casts the public key to a byte slice
func (shared *Shared) Slice() []byte { return shared[:] }

// Slice casts the id to a byte slice
func (id *ID) Slice() []byte { return id[:] }

// Slice casts the nonce to a byte slice
func (nonce *Nonce) Slice() []byte { return nonce[:] }

// String returns the base64 encoding of the public key
func (pub *Pub) String() string { return encodeToString(pub[:]) }

// String returns the base64 encoding of the private key
func (priv *Priv) String() string { return encodeToString(priv[:]) }

// String returns the base64 encoding of the shared key
func (shared *Shared) String() string { return encodeToString(shared[:]) }

// String returns the base64 encoding of the id
func (id *ID) String() string { return encodeToString(id[:]) }

// String returns the base64 encoding of the nonce
func (nonce *Nonce) String() string { return encodeToString(nonce[:]) }

// GenerateKey returns a public and private key.
func GenerateKey() (*Pub, *Priv) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	randReadErr(err)
	return (*Pub)(pub), (*Priv)(priv)
}

// RandomShared returns a random shared key that can be used for symmetric
// ciphers
func RandomShared() *Shared {
	b := make([]byte, KeyLength)
	_, err := rand.Read(b)
	if randReadErr(err) {
		return nil
	}

	s := &Shared{}
	copy(s[:], b)
	return s
}

// KeyPairFromString takes a two base64 encoded strings and returns a keypair
func KeyPairFromString(pubStr, privStr string) (*Pub, *Priv, error) {
	pub, err := PubFromString(pubStr)
	if err != nil {
		return nil, nil, err
	}
	priv, err := PrivFromString(privStr)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// PubFromString takes a base64 encoded public key and returns it as a Pub
func PubFromString(pubStr string) (*Pub, error) {
	key, err := keyFromString(pubStr)
	if err != nil {
		return nil, err
	}

	p := Pub(*key)
	return &p, nil
}

// PrivFromString takes a base64 encoded public key and returns it as a Priv
func PrivFromString(privStr string) (*Priv, error) {
	key, err := keyFromString(privStr)
	if err != nil {
		return nil, err
	}

	p := Priv(*key)
	return &p, nil
}

// SharedFromString takes a base64 encoded public key and returns it as a Shared
func SharedFromString(sharedStr string) (*Shared, error) {
	key, err := keyFromString(sharedStr)
	if err != nil {
		return nil, err
	}

	s := Shared(*key)
	return &s, nil
}

func keyFromString(str string) (*key, error) {
	key := &key{}

	data, err := decodeString(str)
	if err != nil {
		return nil, err
	}
	copy(key[:], data)

	return key, nil
}

// PubFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func PubFromSlice(bs []byte) *Pub {
	pub := Pub(*keyFromSlice(bs))
	return &pub
}

// PrivFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func PrivFromSlice(bs []byte) *Priv {
	priv := Priv(*keyFromSlice(bs))
	return &priv
}

// SharedFromSlice converts a byte slice to a public key. The values are copied, so
// the slice can be modified after.
func SharedFromSlice(bs []byte) *Shared {
	shared := Shared(*keyFromSlice(bs))
	return &shared
}

func keyFromSlice(bs []byte) *key {
	key := &key{}
	copy(key[:], bs)
	return key
}

// GetID returns the ID for a public key.
func (pub *Pub) GetID() *ID {
	h := sha256.New()
	h.Write(pub[:])
	id := &ID{}
	copy(id[:], h.Sum(nil)[:IDLength])
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
func (priv *Priv) GetKeyRef() *KeyRef {
	h := sha256.New()
	h.Write(priv[:])
	keyRef := &KeyRef{}
	copy(keyRef[:], h.Sum(nil)[:IDLength])
	return keyRef
}

// Precompute returns a Shared key from a public and private key
func (pub *Pub) Precompute(priv *Priv) *Shared {
	shared := &Shared{}
	box.Precompute(shared.Arr(), pub.Arr(), priv.Arr())
	return shared
}

// Seal will seal message using a shared key and the given nonce. If the nonce
// is nil, a random nonce is generated. Decyrpted with Open
func (shared *Shared) Seal(msg []byte, nonce *Nonce) []byte {
	out := make([]byte, NonceLength, len(msg)+box.Overhead+NonceLength)
	if nonce == nil {
		nonce = RandomNonce()
	}
	copy(out, nonce[:])

	return box.SealAfterPrecomputation(out, msg, nonce.Arr(), shared.Arr())
}

// SealPackets will seal message using a shared key and the given nonce. If the
// nonce is nil, a random nonce is generated. The tag will be prepended, but
// not encrypted. Trim removes tags from the start of each packet.
func (shared *Shared) SealPackets(tag []byte, msgs [][]byte, nonce *Nonce, trim int) [][]byte {
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
		pkts[i] = box.SealAfterPrecomputation(pkt, msg[trim:], nonce.Arr(), shared.Arr())
		nonce.Inc()
	}

	return pkts
}

// RandomNonce returns a Nonce with a cryptographically random value.
func RandomNonce() *Nonce {
	nonce := &Nonce{}
	_, err := rand.Read(nonce[:])
	if randReadErr(err) {
		return nil
	}
	return nonce
}

// SealAll seals many messages with the same shared key. If nonce is nil, a
// random nonce will be generated for each message.
func (shared *Shared) SealAll(msgs [][]byte, nonce *Nonce) [][]byte {
	if nonce == nil {
		nonce = RandomNonce()
	}
	ciphers := make([][]byte, len(msgs))
	for i, msg := range msgs {
		ciphers[i] = shared.Seal(msg, nonce)
		nonce.Inc()
	}
	return ciphers
}

// ErrDecryptionFailed when no other information is available
const ErrDecryptionFailed = errors.String("Decryption Failed")

// Open will decipher a message ciphered with Seal.
func (shared *Shared) Open(cipher []byte) ([]byte, error) {
	if cipher == nil {
		return nil, nil
	}
	nonce := &Nonce{}
	if len(cipher) < NonceLength {
		return nil, ErrDecryptionFailed
	}
	copy(nonce[:], cipher[:NonceLength])

	data, ok := box.OpenAfterPrecomputation(nil, cipher[NonceLength:], nonce.Arr(), shared.Arr())
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return data, nil
}

// NonceOpen will decipher a message with a specific nonce
func (shared *Shared) NonceOpen(cipher []byte, nonce *Nonce) ([]byte, error) {
	if cipher == nil {
		return nil, nil
	}
	if nonce == nil {
		nonce = zeroNonce
	}
	data, ok := box.OpenAfterPrecomputation(nil, cipher, nonce.Arr(), shared.Arr())
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return data, nil
}

var zeroNonce = &Nonce{}

// AnonSeal encrypts a message with a random key pair. The Nonce is always 0 and
// the public key is prepended to the cipher. The recipient can open the message
// but the sender remains anonymous.
func (pub *Pub) AnonSeal(msg []byte) []byte {
	cipher, _ := pub.AnonSealShared(nil, msg)
	return cipher
}

// TagAnonSeal encrypts a message with a random key pair and prepends a byte
// slice tag. The Nonce is always 0 and the public key is prepended to the
// cipher. The recipient can open the message but the sender remains anonymous.
func (pub *Pub) TagAnonSeal(tag, msg []byte) []byte {
	cipher, _ := pub.AnonSealShared(tag, msg)
	return cipher
}

// AnonOpen decrypts a cipher from AnonSeal or AnonSealShared.
func (priv *Priv) AnonOpen(cipher []byte) ([]byte, error) {
	msg, _, err := priv.AnonOpenShared(cipher)
	return msg, err
}

// AnonSealShared encrypts a message with a random key pair. The Nonce is always
// 0 and the public key is prepended to the cipher. The recipient can open the
// message but the sender remains anonymous. This method also returns the shared
// key for the message.
func (pub *Pub) AnonSealShared(tag, msg []byte) ([]byte, *Shared) {
	otkPub, otkPriv := GenerateKey()
	shared := pub.Precompute(otkPriv)
	l := len(tag)
	bts := make([]byte, l+KeyLength, box.Overhead+l+len(msg))
	copy(bts, tag)
	copy(bts[l:], otkPub[:])
	return box.SealAfterPrecomputation(bts, msg, zeroNonce.Arr(), shared.Arr()), shared
}

// AnonOpenShared decrypts a cipher from AnonSeal or AnonSealShared and returns
// the shared key.
func (priv *Priv) AnonOpenShared(cipher []byte) ([]byte, *Shared, error) {
	if len(cipher) <= KeyLength {
		return nil, nil, ErrDecryptionFailed
	}
	otkPub := &Pub{}
	copy(otkPub[:], cipher[:KeyLength])
	shared := otkPub.Precompute(priv)

	msg, ok := box.OpenAfterPrecomputation(nil, cipher[KeyLength:], zeroNonce.Arr(), shared.Arr())
	if !ok {
		return nil, nil, ErrDecryptionFailed
	}
	return msg, shared, nil
}

// Inc increments the Nonce
func (nonce *Nonce) Inc() *Nonce {
	for i, v := range nonce {
		nonce[i]++
		if v != 255 {
			break
		}
	}
	return nonce
}

// RandInt returns a random int generated using crypto/rand
func RandInt(max int) int {
	bits := 0
	for c := max; c > 0; bits++ {
		c >>= 1
	}
	for {
		r := randBits(bits)
		if r < max {
			return r
		}
	}
}

func randBits(bits int) int {
	b := make([]byte, (bits/8)+1)
	_, err := rand.Read(b)
	randReadErr(err)
	var i int
	for ; bits > 8; bits -= 8 {
		i <<= 8
		i += int(b[0])
		b = b[1:]
	}
	i <<= uint(bits)
	var mask byte
	for ; bits > 0; bits-- {
		mask = (mask << 1) + 1
	}
	i += int(b[0] & mask)
	return i
}

// RandUint32 returns a random int generated using crypto/rand
func RandUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	randReadErr(err)
	return (uint32(b[0]) + uint32(b[1])<<8 + uint32(b[2])<<16 + uint32(b[3])<<24)
}

// RandUint16 returns a random int generated using crypto/rand
func RandUint16() uint16 {
	b := make([]byte, 2)
	_, err := rand.Read(b)
	randReadErr(err)
	return (uint16(b[0]) + uint16(b[1])<<8)
}
