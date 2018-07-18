package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

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

func TestNonceSlice(t *testing.T) {
	nonce := RandomNonce()
	assert.Equal(t, nonce, NonceFromSlice(nonce.Slice()))
}

func TestNonceString(t *testing.T) {
	nonce := RandomNonce()
	out, err := NonceFromString(nonce.String())
	assert.NoError(t, err)
	assert.Equal(t, nonce, out)
}
