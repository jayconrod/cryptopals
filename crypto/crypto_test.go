package crypto_test

import (
	"testing"

	"jayconrod.com/cryptopals/crypto"
)

func TestHammingDistance(t *testing.T) {
	dist := crypto.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		t.Errorf("got %d, want 37", dist)
	}
}
