package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"testing"
)

func TestSymmetricExample(t *testing.T) {
	pubA, privA, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	if pubA == nil || privA == nil {
		t.Error("Got nil")
	}
	pubB, privB, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	if pubB == nil || privB == nil {
		t.Error("Got nil")
	}
	sharedAB := &[32]byte{}
	sharedBA := &[32]byte{}
	box.Precompute(sharedAB, pubA, privB)
	box.Precompute(sharedBA, pubB, privA)
	if !bytes.Equal(sharedAB[:], sharedBA[:]) {
		t.Error("Symmetric secret is not shared")
	}
}

func TestBoxExample(t *testing.T) {
	pubA, privA, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	if pubA == nil || privA == nil {
		t.Error("Got nil")
	}
	pubB, privB, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	if pubB == nil || privB == nil {
		t.Error("Got nil")
	}

	m := make([]byte, 100)
	var n [24]byte // 0
	rand.Read(m)
	c := box.Seal(nil, m, &n, pubA, privB)

	dec, ok := box.Open(nil, c, &n, pubB, privA)
	if !ok {
		t.Error("Check failed")
	}
	if !bytes.Equal(m, dec) {
		t.Error(m)
		t.Error(dec)
		t.Error("Message does not match")
	}
}

func TestECDSA(t *testing.T) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	hash := make([]byte, 255)
	for i := 0; i < 255; i++ {
		hash[i] = byte(i)
	}

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		t.Error(err)
		return
	}

	verified := ecdsa.Verify(&priv.PublicKey, hash, r, s)
	if !verified {
		t.Error("Verification failed")
	}
}

func TestCurve25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, pub)
	assert.NotNil(t, priv)

	assert.Equal(t, KeyLength, len(pub))
	assert.Equal(t, SignPrivLength, len(priv))

	data := make([]byte, 1000)
	rand.Read(data)

	// sig is 64 bytes
	sig := ed25519.Sign(priv, data)
	assert.True(t, ed25519.Verify(pub, data, sig))
}
