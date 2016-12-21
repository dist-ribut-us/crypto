package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDigest(t *testing.T) {
	b := []byte("this is a test")
	d := SHA256(b)

	expect := []byte{
		46, 153, 117, 133, 72, 151, 42, 142,
		136, 34, 173, 71, 250, 16, 23, 255,
		114, 240, 111, 63, 246, 160, 22, 133,
		31, 69, 195, 152, 115, 43, 197, 12,
	}
	assert.Equal(t, expect, []byte(d))
	assert.Equal(t, "Lpl1hUiXKo6IIq1H+hAX/3Lwbz/2oBaFH0XDmHMrxQw=", d.String())
	d2, err := DigestFromString(d.String())
	assert.NoError(t, err)
	assert.True(t, d.Equal(d2))

	assert.Equal(t, "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c", d.Hex())
	d2, err = DigestFromHex(d.Hex())
	assert.True(t, d.Equal(d2))

	assert.Equal(t, SHA256(b), d)
}
