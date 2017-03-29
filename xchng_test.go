package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateXchgKeypair(t *testing.T) {
	pu, pr := GenerateXchgKeypair()
	assert.NotNil(t, pu, "XchgPublic key should not be nil")
	assert.NotNil(t, pr, "XchgPrivate key should not be nil")
}

func TestGenerateID(t *testing.T) {
	pu, pr := GenerateXchgKeypair()
	assert.NotNil(t, pu, "XchgPublic key should not be nil")
	assert.NotNil(t, pr, "XchgPrivate key should not be nil")

	id := pu.GetID()
	assert.NotNil(t, id, "id should not be nil")
}

func TestNonceBox(t *testing.T) {
	pubA, privA := GenerateXchgKeypair()
	pubB, privB := GenerateXchgKeypair()
	shared := pubA.Shared(privB)
	assert.NotNil(t, shared, "shared should not be nil")

	assert.Equal(t, pubA.Shared(privB), pubB.Shared(privA))

	msgA := make([]byte, 100)
	rand.Read(msgA)

	cipher := shared.Seal(msgA, nil)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)

	// confirm that a bad key fails to decrypt in the correct manor
	badKey := RandomSymmetric()
	badMsg, err := badKey.Open(cipher)
	assert.Equal(t, ErrDecryptionFailed, err)
	assert.Nil(t, badMsg)
}

func TestAnon(t *testing.T) {
	pub, priv := GenerateXchgKeypair()
	assert.NotNil(t, pub, "XchgPublic key should not be nil")
	assert.NotNil(t, priv, "XchgPrivate key should not be nil")

	msg := make([]byte, 100)
	rand.Read(msg)

	c, s1 := pub.AnonSealSymmetric([]byte{1, 2, 3}, msg)
	assert.Equal(t, []byte{1, 2, 3}, c[:3])
	p, s2, err := priv.AnonOpenSymmetric(c[3:])
	assert.NoError(t, err)
	assert.Equal(t, s1, s2)
	assert.Equal(t, msg, p)

	p, err = priv.AnonOpen(pub.AnonSeal(msg))
	assert.NoError(t, err)
	assert.Equal(t, msg, p)
}

func TestStringRoundTrips(t *testing.T) {
	pub, priv := GenerateXchgKeypair()
	assert.NotNil(t, pub, "XchgPublic key should not be nil")
	assert.NotNil(t, priv, "XchgPrivate key should not be nil")

	pubRT, err := XchgPubFromString(pub.String())
	assert.NoError(t, err)
	assert.Equal(t, pub, pubRT)

	privRT, err := XchgPrivFromString(priv.String())
	assert.NoError(t, err)
	assert.Equal(t, priv, privRT)

	shared := RandomSymmetric()
	assert.NotNil(t, shared)
	sharedRT, err := SymmetricFromString(shared.String())
	assert.NoError(t, err)
	assert.Equal(t, shared, sharedRT)
}

func TestSliceRoundTrips(t *testing.T) {
	pub, priv := GenerateXchgKeypair()
	assert.NotNil(t, pub, "XchgPublic key should not be nil")
	assert.NotNil(t, priv, "XchgPrivate key should not be nil")

	pubRT := XchgPubFromSlice(pub.Slice())
	assert.Equal(t, pub, pubRT)

	privRT := XchgPrivFromSlice(priv.Slice())
	assert.Equal(t, priv, privRT)

	shared := RandomSymmetric()
	assert.NotNil(t, shared)
	sharedRT := SymmetricFromSlice(shared.Slice())
	assert.Equal(t, shared, sharedRT)
}
