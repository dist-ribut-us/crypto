package crypto

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNonceBoxWithRandom(t *testing.T) {
	shared := RandomSymmetric()
	assert.NotNil(t, shared, "shared should not be nil")

	msgA := make([]byte, 24)
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

func TestRandomSymmetric(t *testing.T) {
	msg := []byte("This is a test")
	s := RandomSymmetric()
	c := s.Seal(msg, nil)

	out, err := s.Open(c)
	assert.NoError(t, err)

	assert.Equal(t, msg, out)
}

func TestSealPackets(t *testing.T) {
	shared := RandomSymmetric()

	msgs := make([][]byte, 10)
	for i := range msgs {
		msgs[i] = make([]byte, 100)
		rand.Read(msgs[i])
	}
	pkts := shared.SealPackets([]byte{111}, msgs, nil, 2)

	for i, pkt := range pkts {
		assert.EqualValues(t, 111, pkt[0])
		msg, err := shared.Open(pkt[1:])
		assert.NoError(t, err)
		assert.Equal(t, msgs[i][2:], msg)
	}
}

func TestNonceEnd2End(t *testing.T) {
	shared := RandomSymmetric()
	assert.NotNil(t, shared, "shared should not be nil")

	msg := make([]byte, 100)
	rand.Read(msg)

	nonce := RandomNonce()

	cipher := shared.NonceSeal(msg, nonce)
	plain, err := shared.NonceOpen(cipher, nonce)
	assert.NoError(t, err)
	assert.Equal(t, msg, plain)
}
