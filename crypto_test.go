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

	cipher := shared.Seal(msgA)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)
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
