package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateXchgPair(t *testing.T) {
	pair := GenerateXchgPair()
	assert.NotNil(t, pair)
	assert.NotNil(t, pair.Pub())
	assert.NotNil(t, pair.Priv())
}

func TestNonceBox(t *testing.T) {
	a := GenerateXchgPair()
	b := GenerateXchgPair()
	shared := b.Shared(a.Pub())
	assert.NotNil(t, shared)

	assert.Equal(t, b.Shared(a.Pub()), a.Shared(b.Pub()))

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
	pair := GenerateXchgPair()

	msg := make([]byte, 100)
	rand.Read(msg)

	c, s1 := pair.AnonSealSymmetric([]byte{1, 2, 3}, msg)
	assert.Equal(t, []byte{1, 2, 3}, c[:3])
	p, s2, err := pair.AnonOpenSymmetric(c[3:])
	assert.NoError(t, err)
	assert.Equal(t, s1, s2)
	assert.Equal(t, msg, p)

	p, err = pair.AnonOpen(pair.AnonSeal(msg))
	assert.NoError(t, err)
	assert.Equal(t, msg, p)
}

func TestStringRoundTrips(t *testing.T) {
	pair := GenerateXchgPair()

	pubRT, err := XchgPubFromString(pair.Pub().String())
	assert.NoError(t, err)
	assert.Equal(t, pair.Pub(), pubRT)

	privRT, err := XchgPrivFromString(pair.Priv().String())
	assert.NoError(t, err)
	assert.Equal(t, pair.Priv(), privRT)

	pairRT, err := XchgPairFromString(pair.String())
	assert.NoError(t, err)
	assert.Equal(t, pair, pairRT)

	shared := RandomSymmetric()
	assert.NotNil(t, shared)
	sharedRT, err := SymmetricFromString(shared.String())
	assert.NoError(t, err)
	assert.Equal(t, shared, sharedRT)
}

func TestSliceRoundTrips(t *testing.T) {
	pair := GenerateXchgPair()

	pubRT := XchgPubFromSlice(pair.Pub().Slice())
	assert.Equal(t, pair.Pub(), pubRT)

	privRT := XchgPrivFromSlice(pair.Priv().Slice())
	assert.Equal(t, pair.Priv(), privRT)

	pairRT := XchgPairFromSlice(pair.Slice())
	assert.Equal(t, pair, pairRT)

	shared := RandomSymmetric()
	assert.NotNil(t, shared)
	sharedRT := SymmetricFromSlice(shared.Slice())
	assert.Equal(t, shared, sharedRT)
}
