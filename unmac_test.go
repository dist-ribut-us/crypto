package crypto

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmacd(t *testing.T) {
	shared := RandomSymmetric()
	assert.NotNil(t, shared)

	nonce := RandomNonce()

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

func TestReversed(t *testing.T) {
	shared := RandomSymmetric()
	assert.NotNil(t, shared)

	nonce := RandomNonce()

	msg := make([]byte, 100)
	rand.Read(msg)

	// UnmacdOpen and UnmacdSeal are actually arbitrary. UnmacdOpen can be used
	// as seal if UnmacdSeal is used as open
	cipher := shared.UnmacdOpen(msg, nonce)
	plain := shared.UnmacdSeal(cipher, nonce)
	if !bytes.Equal(msg, plain) {
		t.Error(msg)
		t.Error(plain)
		t.Error("Message does not match")
	}
}
