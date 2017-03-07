package crypto

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	pu, pr, err := GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pu, "Public key should not be nil")
	assert.NotNil(t, pr, "Private key should not be nil")
}

func TestGenerateID(t *testing.T) {
	pu, pr, err := GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pu, "Public key should not be nil")
	assert.NotNil(t, pr, "Private key should not be nil")

	id := pu.GetID()
	assert.NotNil(t, id, "id should not be nil")
}

func TestNonceBox(t *testing.T) {
	pubA, _, err := GenerateKey()
	assert.NoError(t, err)
	_, privB, err := GenerateKey()
	assert.NoError(t, err)
	shared := pubA.Precompute(privB)
	assert.NotNil(t, shared, "shared should not be nil")

	msgA := make([]byte, 100)
	rand.Read(msgA)

	cipher := shared.Seal(msgA, nil)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)

	// confirm that a bad key fails to decrypt in the correct manor
	badKey, err := RandomShared()
	assert.NoError(t, err)
	badMsg, err := badKey.Open(cipher)
	assert.Equal(t, ErrDecryptionFailed, err)
	assert.Nil(t, badMsg)
}

func TestNonceBoxWithRandom(t *testing.T) {
	shared, err := RandomShared()
	assert.NoError(t, err)
	assert.NotNil(t, shared, "shared should not be nil")

	msgA := make([]byte, 24)
	rand.Read(msgA)

	cipher := shared.Seal(msgA, nil)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)

	// confirm that a bad key fails to decrypt in the correct manor
	badKey, err := RandomShared()
	assert.NoError(t, err)
	badMsg, err := badKey.Open(cipher)
	assert.Equal(t, ErrDecryptionFailed, err)
	assert.Nil(t, badMsg)
}

func TestAnon(t *testing.T) {
	pub, priv, err := GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	msg := make([]byte, 100)
	rand.Read(msg)

	ciph, err := pub.AnonSeal(msg)
	assert.NoError(t, err)
	deci, err := priv.AnonOpen(ciph)
	assert.NoError(t, err)
	assert.Equal(t, msg, deci)
}

func TestUnmacd(t *testing.T) {
	pubA, _, err := GenerateKey()
	assert.NoError(t, err)
	_, privB, err := GenerateKey()
	assert.NoError(t, err)
	shared := pubA.Precompute(privB)
	if shared == nil {
		t.Error("Got nil")
	}

	nonce := &Nonce{}
	nonce[0] = 1

	msg := make([]byte, 100)
	rand.Read(msg)

	cipher := shared.UnmacdSeal(msg, nonce)
	plain := shared.UnmacdOpen(cipher, nonce)
	if !bytes.Equal(msg, plain) {
		t.Error(msg)
		t.Error(plain)
		t.Error("Message does not match")
	}
}

func TestNonceInc(t *testing.T) {
	n := Nonce{}
	n[0] = 255
	n[1] = 255
	n[2] = 5
	n.Inc()
	expected := Nonce{}
	expected[2] = 6
	assert.Equal(t, expected, n)
}

func TestRandomShared(t *testing.T) {
	msg := []byte("This is a test")
	s, err := RandomShared()
	assert.NoError(t, err)

	c := s.Seal(msg, nil)

	out, err := s.Open(c)
	assert.NoError(t, err)

	assert.Equal(t, msg, out)
}

func TestStringRoundTrips(t *testing.T) {
	pub, priv, err := GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	pubRT, err := PubFromString(pub.String())
	assert.NoError(t, err)
	assert.Equal(t, pub, pubRT)

	privRT, err := PrivFromString(priv.String())
	assert.NoError(t, err)
	assert.Equal(t, priv, privRT)

	shared, err := RandomShared()
	assert.NoError(t, err)
	assert.NotNil(t, shared)
	sharedRT, err := SharedFromString(shared.String())
	assert.NoError(t, err)
	assert.Equal(t, shared, sharedRT)
}

func TestSliceRoundTrips(t *testing.T) {
	pub, priv, err := GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	pubRT := PubFromSlice(pub.Slice())
	assert.Equal(t, pub, pubRT)

	privRT := PrivFromSlice(priv.Slice())
	assert.Equal(t, priv, privRT)

	shared, err := RandomShared()
	assert.NoError(t, err)
	assert.NotNil(t, shared)
	sharedRT := SharedFromSlice(shared.Slice())
	assert.Equal(t, shared, sharedRT)
}
