package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestSet4Problem29(t *testing.T) {
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	key := []byte("YELLOW SUBMARINE")

	padLength := func(n uint64) uint64 {
		return (n + 9 + 63) / 64 * 64
	}

	makePadding := func(n uint64) []byte {
		padded := padLength(n)
		p := int(padded - n)
		b := make([]byte, p)
		b[0] = 0x80
		binary.BigEndian.PutUint64(b[p-8:], n*8)
		return b
	}

	want := crypto.SHA1Sum(msg)
	h := crypto.NewSHA1()
	h.Write(msg)
	h.Write(makePadding(uint64(len(msg))))
	_, got := h.Get()
	if !bytes.Equal(got[:], want[:]) {
		t.Fatal("appendPadding does not produce the correct state")
	}

	prefixMac := func(key, msg []byte) [20]byte {
		mt := append(key, msg...)
		return crypto.SHA1Sum(mt)
	}

	checkPrefixMac := func(key, msg []byte, mac [20]byte) {
		got := prefixMac(key, msg)
		if !bytes.Equal(got[:], mac[:]) {
			t.Fatal("MAC mismatch")
		}
	}

	extendPrefixMac := func(keyLen int, msg []byte, mac [20]byte, more []byte) (xmsg []byte, xmac [20]byte) {
		origLen := keyLen + len(msg)
		xmsg = append(msg, makePadding(uint64(origLen))...)
		xmsg = append(xmsg, more...)

		h := crypto.NewSHA1()
		n := uint64(len(xmsg) - len(more) + keyLen)
		h.Set(n, mac)
		h.Write(more)
		h.Sum(xmac[:0])
		return xmsg, xmac
	}

	mac := prefixMac(key, msg)
	checkPrefixMac(key, msg, mac)
	xmsg, xmac := extendPrefixMac(len(key), msg, mac, []byte(";admin=true"))
	checkPrefixMac(key, xmsg, xmac)
}

func TestSet4Problem30(t *testing.T) {
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	key := []byte("YELLOW SUBMARINE")

	padLength := func(n uint64) uint64 {
		return (n + 9 + crypto.MD4BlockSize - 1) / crypto.MD4BlockSize * crypto.MD4BlockSize
	}

	makePadding := func(n uint64) []byte {
		padded := padLength(n)
		p := int(padded - n)
		b := make([]byte, p)
		b[0] = 0x80
		binary.LittleEndian.PutUint64(b[p-8:], n*8)
		return b
	}

	want := crypto.MD4Sum(msg)
	h := crypto.NewMD4()
	h.Write(msg)
	h.Write(makePadding(uint64(len(msg))))
	_, got := h.Get()
	if !bytes.Equal(got[:], want[:]) {
		t.Fatal("appendPadding does not produce the correct state")
	}

	prefixMac := func(key, msg []byte) [crypto.MD4Size]byte {
		mt := append(key, msg...)
		return crypto.MD4Sum(mt)
	}

	checkPrefixMac := func(key, msg []byte, mac [crypto.MD4Size]byte) {
		got := prefixMac(key, msg)
		if !bytes.Equal(got[:], mac[:]) {
			t.Fatal("MAC mismatch")
		}
	}

	extendPrefixMac := func(keyLen int, msg []byte, mac [crypto.MD4Size]byte, more []byte) (xmsg []byte, xmac [crypto.MD4Size]byte) {
		origLen := keyLen + len(msg)
		xmsg = append(msg, makePadding(uint64(origLen))...)
		xmsg = append(xmsg, more...)

		h := crypto.NewMD4()
		n := uint64(len(xmsg) - len(more) + keyLen)
		h.Set(n, mac)
		h.Write(more)
		h.Sum(xmac[:0])
		return xmsg, xmac
	}

	mac := prefixMac(key, msg)
	checkPrefixMac(key, msg, mac)
	xmsg, xmac := extendPrefixMac(len(key), msg, mac, []byte(";admin=true"))
	checkPrefixMac(key, xmsg, xmac)
}

func TestHMACSHA1(t *testing.T) {
	data := readBase64File(t, filepath.FromSlash("testdata/s2/p10.txt"))
	for _, test := range []struct {
		desc string
		key  []byte
	}{
		{
			desc: "short_key",
			key:  []byte("YELLOW SUBMARINE"),
		},
		{
			desc: "long_key",
			key:  []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"),
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			got := crypto.HMACSHA1(test.key, data)
			var want [crypto.SHA1Size]byte
			hmac := hmac.New(sha1.New, test.key)
			hmac.Write(data)
			hmac.Sum(want[:0])
			if !bytes.Equal(got[:], want[:]) {
				t.Errorf("HMAC implementation does not match\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
			}
		})
	}
}

func TestSet4Problem31(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// key is shared by the client and server.
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// data is sent by the client, together with a MAC. The server verifies the
	// key was used to generate the MAC.
	data := make([]byte, 8192)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	correctTag := crypto.HMACSHA1(key, data)

	// insecureVerifyMAC generates a tag on the given data with the shared key,
	// then returns whether it matches the given tag. It sleeps for a short time
	// after each character. I'm too lazy to stand up an HTTP server for this like
	// the problem asks for, so this is a substitute.
	insecureVerifyMAC := func(data, tag []byte) bool {
		for i := 0; i < len(correctTag); i++ {
			if correctTag[i] != tag[i] {
				return false
			}
			time.Sleep(170 * time.Microsecond)
		}
		return true
	}

	// Determine correctTag, based on timing leaks.
	var tags [256][crypto.SHA1Size]byte
	var elapsed [256]time.Duration
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i := 0; i < crypto.SHA1Size; i++ {
		// Each iteration of the outer loop determines the next byte.
		for j := 0; j < 256; j++ {
			// Each iteration of the inner loop tries one value in parallel.
			// We repeat the evaluation to smooth out scheduling noise.
			j := j
			sem <- struct{}{}
			go func() {
				begin := time.Now()
				tags[j][i] = byte(j)
				for k := 0; k < 3; k++ {
					insecureVerifyMAC(data, tags[j][:])
				}
				elapsed[j] = time.Now().Sub(begin)
				<-sem
			}()
		}

		// Fill the channel to ensure all goroutines finished, then drain it.
		for j := 0; j < cap(sem); j++ {
			sem <- struct{}{}
		}
		for j := 0; j < cap(sem); j++ {
			<-sem
		}

		// The byte that took the longest is the correct one.
		// Copy it to other buffers.
		var maxElapsed time.Duration
		var b byte
		for j := 0; j < 256; j++ {
			if elapsed[j] > maxElapsed {
				maxElapsed = elapsed[j]
				b = byte(j)
			}
		}
		for j := 0; j < 256; j++ {
			tags[j][i] = b
		}
	}
	if !bytes.Equal(tags[0][:], correctTag[:]) {
		t.Fatalf("could not infer MAC from timing\n got %s\nwant %s", hex.EncodeToString(tags[0][:]), hex.EncodeToString(correctTag[:]))
	}
}

func TestSet4Problem32(t *testing.T) {
	// No code here; I just adjusted the code from problem 31.
	//
	// 170 us was the lowest I could go without occasionally failing. When
	// measuring time, I loop over three calls and measure the total duration.
	//
	// I'm sure a real network would be noisier than this, so it would be better
	// to measure durations of several requests and look for statistically
	// significant differences. More requests may be needed for later bytes, since
	// the relative timing differences are smaller at the end.
}
