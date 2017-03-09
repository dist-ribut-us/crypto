package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDigest(t *testing.T) {
	b := []byte("this is a test")
	d := GetDigest(b)
	assert.NotNil(t, d)

	expect := []byte{
		46, 153, 117, 133, 72, 151, 42, 142,
		136, 34, 173, 71, 250, 16, 23, 255,
		114, 240, 111, 63, 246, 160, 22, 133,
		31, 69, 195, 152, 115, 43, 197, 12,
	}
	assert.Equal(t, expect, d[:])
	assert.Equal(t, "Lpl1hUiXKo6IIq1H+hAX/3Lwbz/2oBaFH0XDmHMrxQw=", d.String())
	d2, err := DigestFromString(d.String())
	assert.NoError(t, err)
	assert.True(t, d.Equal(d2))

	assert.Equal(t, "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c", d.Hex())
	d2, err = DigestFromHex(d.Hex())
	assert.True(t, d.Equal(d2))

	assert.Equal(t, GetDigest(b), d)
}

func TestHasher(t *testing.T) {
	h := Hash([]byte("this is "))
	h.Write([]byte("a test"))
	d := h.Digest()

	expect := []byte{
		46, 153, 117, 133, 72, 151, 42, 142,
		136, 34, 173, 71, 250, 16, 23, 255,
		114, 240, 111, 63, 246, 160, 22, 133,
		31, 69, 195, 152, 115, 43, 197, 12,
	}

	assert.Equal(t, expect, d[:])
}

func TestDigestToShared(t *testing.T) {
	h := Hash([]byte("password"))
	h.Write([]byte("salt"))
	shared := h.Digest().Shared()
	expect := []byte{
		122, 55, 184, 92, 137, 24, 234, 193,
		154, 144, 137, 192, 250, 90, 42, 180,
		220, 227, 249, 5, 40, 220, 222, 236,
		16, 139, 35, 221, 243, 96, 123, 153,
	}
	assert.Equal(t, expect, shared[:])
}
