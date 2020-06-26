package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"jayconrod.com/cryptopals/crypto"
)

func TestSet1Problem1(t *testing.T) {
	t.Parallel()
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	data, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	got := base64.StdEncoding.EncodeToString(data)
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSet1Problem2(t *testing.T) {
	t.Parallel()
	a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}
	c := crypto.XOR(nil, a, b)
	got := hex.EncodeToString(c)
	want := "746865206b696420646f6e277420706c6179"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSet1Problem3(t *testing.T) {
	t.Parallel()
	ct, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Fatal(err)
	}
	_, _, pt := crypto.CrackXORByte(ct)
	got := string(pt)
	want := "Cooking MC's like a pound of bacon"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSet1Problem4(t *testing.T) {
	t.Parallel()
	data := readFile(t, filepath.Join("testdata/s1/p4.txt"))
	bestScore := math.Inf(1.)
	var bestPT []byte
	for _, line := range strings.Split(string(data), "\n") {
		ct, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		_, score, pt := crypto.CrackXORByte(ct)
		if score < bestScore {
			bestScore = score
			bestPT = pt
		}
	}
	got := string(bestPT)
	want := "Now that the party is jumping\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSet1Problem5(t *testing.T) {
	t.Parallel()
	pt := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	key := []byte("ICE")
	ct := crypto.XORRepeat(nil, pt, key)
	got := hex.EncodeToString(ct)
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestSet1Problem6(t *testing.T) {
	t.Parallel()
	ct := readBase64File(t, filepath.FromSlash("testdata/s1/p6.txt"))
	_, pt, err := crypto.CrackXORRepeat(ct, 2, 40)
	if err != nil {
		t.Fatal(err)
	}
	want := readFile(t, filepath.FromSlash("testdata/s1/p6want.txt"))
	if !bytes.Equal(pt, want) {
		t.Errorf("got:\n%s\nwant:\n%s", pt, want)
	}
}

func TestSet1Problem7(t *testing.T) {
	t.Parallel()
	key := []byte(`YELLOW SUBMARINE`)
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := readBase64File(t, filepath.FromSlash("testdata/s1/p7.txt"))
	pt := make([]byte, len(ct))
	dec := crypto.NewECBDecrypter(c)
	dec.CryptBlocks(pt, ct)

	want := readBase64File(t, filepath.FromSlash("testdata/s1/p7want.txt"))
	if !bytes.Equal(pt, want) {
		t.Errorf("got:\n%s\nwant:\n%s", pt, want)
	}
}

func TestSet1Problem8(t *testing.T) {
	t.Parallel()
	data, err := ioutil.ReadFile(filepath.FromSlash("testdata/s1/p8.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	found := -1
	for i, line := range lines {
		ct, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		if crypto.DetectECB(ct) {
			found = i
			break
		}
	}
	want := 132
	if found == -1 {
		t.Errorf("did not find ciphertext with repeating blocks")
	} else if found != want {
		t.Errorf("found ECB at index %d; want %d", found, want)
	}
}
