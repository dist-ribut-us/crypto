package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSign(t *testing.T) {
	pub, priv := GenerateSignKeypair()
	assert.NotNil(t, pub)
	assert.NotNil(t, priv)

	msg := make([]byte, 1000)
	rand.Read(msg)

	sig := priv.Sign(msg)
	assert.NotNil(t, sig)
	assert.True(t, pub.Verify(msg, sig))

	assert.Equal(t, pub, priv.Pub())
}
