package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode"

	"jayconrod.com/cryptopals/crypto"
)

func TestSet4Problem25(t *testing.T) {
	origCT := readBase64File(t, "testdata/s1/p7.txt")
	c, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}
	dec := crypto.NewECBDecrypter(c)
	unknownPT := origCT
	dec.CryptBlocks(unknownPT, origCT)

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	iv, key := buf[:16], buf[16:]
	c, err = aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ctr := crypto.NewCTR(c, iv)
	ct := make([]byte, len(unknownPT))
	ctr.XORKeyStream(ct, unknownPT)

	ksb := make([]byte, 16)
	crypto.XOR(ksb, ct[:16], unknownPT[:16])

	edit := func(ct []byte, offset int, newPT []byte) {
		ctr := crypto.NewCTR(c, iv)
		ctr.Seek(offset)
		newCT := ct[offset : offset+len(newPT)]
		ctr.XORKeyStream(newCT, newPT)
	}

	ks := make([]byte, len(ct))
	edit(ks, 0, ks)
	pt := make([]byte, len(ct))
	crypto.XOR(pt, ct, ks)
	if !bytes.Equal(pt, unknownPT) {
		t.Fatal("failed to decrypt")
	}
}

func TestSet4Problem26(t *testing.T) {
	encryptOracle := func(text string) (key, iv, ct []byte) {
		r := strings.NewReplacer(";", "%3B", "=", "%3D")
		text = r.Replace(text)
		pt := []byte("comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon")
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		key, iv = buf[:16], buf[16:]
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		ctr := crypto.NewCTR(c, iv)
		ct = pt
		ctr.XORKeyStream(ct, pt)
		return key, iv, ct
	}

	isAdminOracle := func(key, iv, ct []byte) bool {
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		ctr := crypto.NewCTR(c, iv)
		pt := make([]byte, len(ct))
		ctr.XORKeyStream(pt, ct)
		return bytes.Index(pt, []byte(";admin=true;")) >= 0
	}

	text := strings.Repeat("\x00", 16)
	unknownKey, unknownIV, ct := encryptOracle(text)
	b := ct[32:48]
	crypto.XOR(b, b, []byte("\x00\x00\x00\x00\x00;admin=true"))
	if !isAdminOracle(unknownKey, unknownIV, ct) {
		t.Fatal("failed to make admin")
	}
}

func TestSet4Problem27(t *testing.T) {
	unknownKey := make([]byte, 16)
	if _, err := rand.Read(unknownKey); err != nil {
		t.Fatal(err)
	}
	unknownPT := []byte("Using the key as an IV is insecure; an attacker ")

	encryptOracle := func() (ct []byte) {
		c, err := aes.NewCipher(unknownKey)
		if err != nil {
			t.Fatal(err)
		}
		enc := crypto.NewCBCEncrypter(c, unknownKey)
		ct = make([]byte, len(unknownPT))
		enc.CryptBlocks(ct, unknownPT)
		return ct
	}

	decryptOracle := func(ct []byte) error {
		c, err := aes.NewCipher(unknownKey)
		if err != nil {
			t.Fatal(err)
		}
		dec := crypto.NewCBCDecrypter(c, unknownKey)
		pt := make([]byte, len(ct))
		dec.CryptBlocks(pt, ct)
		for _, b := range pt {
			if b > unicode.MaxASCII {
				return &asciiDecryptError{pt: pt}
			}
		}
		return nil
	}

	ct := encryptOracle()
	for i := 16; i < 32; i++ {
		ct[i] = 0
	}
	copy(ct[32:48], ct[:16])
	var decErr *asciiDecryptError
	if err := decryptOracle(ct); err == nil {
		t.Fatal("unexpected success")
	} else if !errors.As(err, &decErr) {
		t.Fatalf("unexpected error: %v", err)
	}

	key := make([]byte, 16)
	crypto.XOR(key, decErr.pt[:16], decErr.pt[32:])
	if !bytes.Equal(key, unknownKey) {
		t.Fatal("failed to extract key")
	}
}

type asciiDecryptError struct {
	pt []byte
}

func (e *asciiDecryptError) Error() string {
	return fmt.Sprintf("invalid message: %q", e.pt)
}

func TestSet4Problem28(t *testing.T) {
	msg := []byte("bleep bloop")
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	mt := append(key, msg...)
	stdSum := sha1.Sum(mt)
	customSum := crypto.SHA1Sum(mt)
	if !bytes.Equal(stdSum[:], customSum[:]) {
		t.Fatal("custom implementation produces wrong sum")
	}
}
