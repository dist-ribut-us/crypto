package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSign(t *testing.T) {
	pub, priv := GenerateSignPair()
	assert.NotNil(t, pub)
	assert.NotNil(t, priv)

	msg := make([]byte, 1000)
	rand.Read(msg)

	sig := priv.Sign(msg)
	assert.NotNil(t, sig)
	assert.True(t, pub.Verify(msg, sig))

	assert.Equal(t, pub, priv.Pub())
}

func TestGenerateID(t *testing.T) {
	pu, err := SignPubFromString("a3_-T-y4xsB88lrhfery7xnXNHIhCtQuSt9nr7AF2vA=")
	assert.NoError(t, err)

	expectedID, err := IDFromString("Kit-Dtm8Fbic6w==")
	assert.Equal(t, expectedID, pu.ID())
}
