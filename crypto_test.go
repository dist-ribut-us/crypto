package crypto

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	pu, pr := GenerateKey()
	assert.NotNil(t, pu, "Public key should not be nil")
	assert.NotNil(t, pr, "Private key should not be nil")
}

func TestGenerateID(t *testing.T) {
	pu, pr := GenerateKey()
	assert.NotNil(t, pu, "Public key should not be nil")
	assert.NotNil(t, pr, "Private key should not be nil")

	id := pu.GetID()
	assert.NotNil(t, id, "id should not be nil")
}

func TestNonceBox(t *testing.T) {
	pubA, privA := GenerateKey()
	pubB, privB := GenerateKey()
	shared := pubA.Precompute(privB)
	assert.NotNil(t, shared, "shared should not be nil")

	assert.Equal(t, pubA.Precompute(privB), pubB.Precompute(privA))

	msgA := make([]byte, 100)
	rand.Read(msgA)

	cipher := shared.Seal(msgA, nil)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)

	// confirm that a bad key fails to decrypt in the correct manor
	badKey := RandomShared()
	badMsg, err := badKey.Open(cipher)
	assert.Equal(t, ErrDecryptionFailed, err)
	assert.Nil(t, badMsg)
}

func TestNonceBoxWithRandom(t *testing.T) {
	shared := RandomShared()
	assert.NotNil(t, shared, "shared should not be nil")

	msgA := make([]byte, 24)
	rand.Read(msgA)

	cipher := shared.Seal(msgA, nil)
	msgB, err := shared.Open(cipher)
	assert.NoError(t, err)
	assert.Equal(t, msgA, msgB)

	// confirm that a bad key fails to decrypt in the correct manor
	badKey := RandomShared()
	badMsg, err := badKey.Open(cipher)
	assert.Equal(t, ErrDecryptionFailed, err)
	assert.Nil(t, badMsg)
}

func TestAnon(t *testing.T) {
	pub, priv := GenerateKey()
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	msg := make([]byte, 100)
	rand.Read(msg)

	c, s1 := pub.AnonSealShared([]byte{1, 2, 3}, msg)
	assert.Equal(t, []byte{1, 2, 3}, c[:3])
	p, s2, err := priv.AnonOpenShared(c[3:])
	assert.NoError(t, err)
	assert.Equal(t, s1, s2)
	assert.Equal(t, msg, p)

	p, err = priv.AnonOpen(pub.AnonSeal(msg))
	assert.NoError(t, err)
	assert.Equal(t, msg, p)
}

func TestUnmacd(t *testing.T) {
	pubA, _ := GenerateKey()
	_, privB := GenerateKey()
	shared := pubA.Precompute(privB)
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
	s := RandomShared()
	c := s.Seal(msg, nil)

	out, err := s.Open(c)
	assert.NoError(t, err)

	assert.Equal(t, msg, out)
}

func TestStringRoundTrips(t *testing.T) {
	pub, priv := GenerateKey()
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	pubRT, err := PubFromString(pub.String())
	assert.NoError(t, err)
	assert.Equal(t, pub, pubRT)

	privRT, err := PrivFromString(priv.String())
	assert.NoError(t, err)
	assert.Equal(t, priv, privRT)

	shared := RandomShared()
	assert.NotNil(t, shared)
	sharedRT, err := SharedFromString(shared.String())
	assert.NoError(t, err)
	assert.Equal(t, shared, sharedRT)
}

func TestSliceRoundTrips(t *testing.T) {
	pub, priv := GenerateKey()
	assert.NotNil(t, pub, "Public key should not be nil")
	assert.NotNil(t, priv, "Private key should not be nil")

	pubRT := PubFromSlice(pub.Slice())
	assert.Equal(t, pub, pubRT)

	privRT := PrivFromSlice(priv.Slice())
	assert.Equal(t, priv, privRT)

	shared := RandomShared()
	assert.NotNil(t, shared)
	sharedRT := SharedFromSlice(shared.Slice())
	assert.Equal(t, shared, sharedRT)
}

func TestSealPackets(t *testing.T) {
	shared := RandomShared()

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

func TestRandInt(t *testing.T) {
	n := 1000
	// This tests that RandInt is uniform and does not have wrapping artifacts
	// around the length of an int
	maxInt := int(^uint(0) >> 1)
	half := (maxInt / 3)
	max := half * 2
	c := 0
	for i := 0; i < n; i++ {
		r := RandInt(max)
		if r > half {
			c++
		}
	}
	assert.InDelta(t, n/2, c, float64(n)/10) // should really find the correct probability here
}
