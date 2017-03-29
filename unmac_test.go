package crypto

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmacd(t *testing.T) {
	pubA, _ := GenerateXchgKeypair()
	_, privB := GenerateXchgKeypair()
	shared := pubA.Shared(privB)
	assert.NotNil(t, shared)

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
