package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"jayconrod.com/cryptopals/crypto"
)

// Implement PKCS#7 padding.
func TestSet2Problem9(t *testing.T) {
	t.Parallel()
	src := []byte("YELLOW SUBMARINE")
	dst := crypto.Pad(nil, src, 20)
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	if !bytes.Equal(dst, want) {
		t.Errorf("got %q; want %q", dst, want)
	}
}

// Implement CBC mode.
func TestSet2Problem10(t *testing.T) {
	t.Parallel()
	ct := readBase64File(t, filepath.FromSlash("testdata/s2/p10.txt"))
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	dec := crypto.NewCBCDecrypter(c, iv)
	pt := make([]byte, len(ct))
	dec.CryptBlocks(pt, ct)

	want := readFile(t, filepath.FromSlash("testdata/s2/p10want.txt"))
	if !bytes.Equal(pt, want) {
		t.Errorf("got:\n%s\nwant:\n%s", pt, want)
	}
}

// ECB/CBC detection oracle.
func TestSet2Problem11(t *testing.T) {
	t.Parallel()

	type mode int
	const (
		ECB mode = 0
		CBC mode = 1
	)
	encryptOracle := func(pt []byte) ([]byte, mode) {
		r := make([]byte, 33)
		if _, err := rand.Read(r); err != nil {
			t.Fatal(err)
		}
		key := r[:16]
		iv := r[16:32]
		config := int(r[32])
		mode := mode(config & 1)
		headJunkLen := (((config >> 1) & 7) % 6) + 5
		tailJunkLen := (((config >> 4) & 7) % 6) + 5
		junk := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		ptJunkLen := headJunkLen + len(pt) + tailJunkLen
		bs := 16
		p := bs - (ptJunkLen % bs)
		paddedPTLen := ptJunkLen + p
		paddedPT := make([]byte, 0, paddedPTLen)
		paddedPT = append(paddedPT, junk[:headJunkLen]...)
		paddedPT = append(paddedPT, pt...)
		paddedPT = append(paddedPT, junk[:tailJunkLen]...)
		paddedPT = crypto.Pad(paddedPT[:0], paddedPT, bs)

		var enc cipher.BlockMode
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		if mode == ECB {
			enc = crypto.NewECBEncrypter(c)
		} else {
			enc = crypto.NewCBCEncrypter(c, iv)
		}
		ct := make([]byte, len(paddedPT))
		enc.CryptBlocks(ct, paddedPT)
		return ct, mode
	}

	for i := 0; i < 10; i++ {
		pt := make([]byte, 64) // at least four blocks ensure repetition in ECB
		ct, want := encryptOracle(pt)
		isECB := crypto.DetectECB(ct)
		if (want == ECB) != isECB {
			t.Errorf("iteration %d: did not detect correct mode: got ECB %t, want ECB %t", i, isECB, want == ECB)
		}
	}
}

// Byte-at-a-time ECB decryption (simple).
func TestSet2Problem12(t *testing.T) {
	t.Parallel()
	unknownPT := readBase64File(t, filepath.FromSlash("testdata/s2/p12.txt"))
	unknownBlockSize := 16
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	encryptOracle := func(prefixPT []byte) []byte {
		n := crypto.PadLength(len(prefixPT)+len(unknownPT), unknownBlockSize)
		buf := make([]byte, n)
		copy(buf, prefixPT)
		copy(buf[len(prefixPT):], unknownPT)
		buf = crypto.Pad(buf[:0], buf[:len(prefixPT)+len(unknownPT)], unknownBlockSize)
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		enc := crypto.NewECBEncrypter(c)
		enc.CryptBlocks(buf, buf)
		return buf
	}

	// Discover block size and length of unknown text.
	prefix := make([]byte, 64)
	m := len(encryptOracle(prefix[:0]))
	var blockSize int
	var ptLen int
	for i := 1; i < len(prefix); i++ {
		n := len(encryptOracle(prefix[:i]))
		if n > m {
			blockSize = n - m
			ptLen = n - blockSize - i
			break
		}
	}
	if blockSize == 0 {
		t.Fatal("couldn't discover block size")
	}
	if blockSize != unknownBlockSize {
		t.Fatalf("got block size %d; want %d", blockSize, unknownBlockSize)
	}
	if ptLen != len(unknownPT) {
		t.Fatalf("got plaintext length %d; want %d", ptLen, len(unknownPT))
	}

	// Detect ECB.
	prefix = make([]byte, 4*blockSize)
	ct := encryptOracle(prefix)
	if !crypto.DetectECB(ct) {
		t.Fatal("did not detect ECB")
	}

	// Encrypt the unknown text with a zero prefixes of every length up to the
	// block size.
	zero := make([]byte, blockSize)
	cts := make([][]byte, blockSize)
	for i := range cts {
		cts[i] = encryptOracle(zero[:i])
	}

	// Decrypt the plaintext.
	pt := make([]byte, ptLen)
	scratch := make([]byte, blockSize)
	for i := 0; i < ptLen; i++ {
		blockIndex := i / blockSize
		byteIndex := i % blockSize

		// Pick a ciphertext such that the first unknown byte is the last byte
		// in a block.
		ct = cts[blockSize-byteIndex-1]
		ctb := ct[blockIndex*blockSize : (blockIndex+1)*blockSize]

		// Try encrypting every possible plaintext block and see what matches.
		found := false
		for j := 0; j < 256 && !found; j++ {
			scratch[blockSize-1] = byte(j)
			db := encryptOracle(scratch)[:blockSize]
			if bytes.Equal(db, ctb) {
				found = true
				pt[i] = byte(j)
			}
		}
		if !found {
			t.Fatalf("did not decrypt byte %d", i)
		}

		copy(scratch[:blockSize-1], scratch[1:])
	}

	want := readFile(t, filepath.FromSlash("testdata/s2/p12want.txt"))
	if !bytes.Equal(pt, want) {
		t.Errorf("got:\n%s\nwant:\n%s", pt, want)
	}
}

// ECB cut-and-paste.
func TestSet2Problem13(t *testing.T) {
	t.Parallel()

	type profile struct {
		email, uid, role string
	}

	parseQuery := func(q string) (profile, error) {
		var p profile
		for _, pair := range strings.Split(q, "&") {
			var key, value string
			if i := strings.Index(pair, "="); i < 0 {
				return profile{}, errors.New("parse error")
			} else {
				key, value = pair[:i], pair[i+1:]
			}
			switch key {
			case "email":
				p.email = value
			case "uid":
				p.uid = value
			case "role":
				p.role = value
			default:
				return profile{}, fmt.Errorf("unknown key: %s", key)
			}
		}
		return p, nil
	}

	profileFor := func(email, uid string) (profile, error) {
		if strings.IndexAny(email, "&=") >= 0 {
			return profile{}, errors.New("email must not contain metacharacters")
		}
		if strings.IndexAny(uid, "&=") >= 0 {
			return profile{}, errors.New("uid must not contain metacharacters")
		}
		return profile{email: email, uid: uid, role: "user"}, nil
	}

	profileToQuery := func(p profile) string {
		return fmt.Sprintf("email=%s&uid=%s&role=%s", p.email, p.uid, p.role)
	}

	const blockSize = 16
	key := make([]byte, blockSize)
	if n, err := rand.Read(key); err != nil || n < blockSize {
		t.Fatal("could not generate key")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewECBEncrypter(c)
	dec := crypto.NewECBDecrypter(c)
	encrypt := func(pt []byte) []byte {
		pt = crypto.Pad(nil, pt, blockSize)
		ct := make([]byte, len(pt))
		enc.CryptBlocks(ct, pt)
		return ct
	}
	encryptedProfileFor := func(email, uid string) ([]byte, error) {
		p, err := profileFor(email, uid)
		if err != nil {
			return nil, err
		}
		pt := []byte(profileToQuery(p))
		return encrypt(pt), nil
	}
	decrypt := func(ct []byte) []byte {
		pt := make([]byte, len(ct))
		dec.CryptBlocks(pt, ct)
		pt, err = crypto.Unpad(pt)
		if err != nil {
			t.Fatal(err)
		}
		return pt
	}

	attack := func() []byte {
		// Encrypt a block with "admin" followed by 11 padding bytes.
		ct, err := encryptedProfileFor("aaaa@b.comadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "10")
		if err != nil {
			t.Fatal(err)
		}
		adminBlock := ct[blockSize : 2*blockSize]

		// Encrypt a normal looking profile, where the role value is the only thing
		// in the last block.
		ct, err = encryptedProfileFor("aaaaaaa@b.com", "10")
		if err != nil {
			t.Fatal(err)
		}
		copy(ct[32:48], adminBlock)
		return ct
	}

	ct := attack()
	pt := decrypt(ct)
	p, err := parseQuery(string(pt))
	if err != nil {
		t.Fatalf("attacker generated invalid plaintext: %v", err)
	}
	if p.role != "admin" {
		t.Errorf("attacker did not produce admin profile")
	}
}

// Byte-at-a-time ECB decryption (harder).
func TestSet2Problem14(t *testing.T) {
	t.Parallel()
	unknownPT := readBase64File(t, filepath.FromSlash("testdata/s2/p12.txt"))
	unknownBlockSize := 16
	key := make([]byte, 16)
	if n, err := rand.Read(key); err != nil || n < len(key) {
		t.Fatalf("could not generate key: %v", err)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	enc := crypto.NewECBEncrypter(c)
	unknownRandomPT := make([]byte, 64)
	if n, err := rand.Read(unknownRandomPT); err != nil || n < len(unknownRandomPT) {
		t.Fatalf("could not generate random prefix: %v", err)
	}
	unknownRandomPTLen := int(unknownRandomPT[len(unknownRandomPT)-1]) % len(unknownRandomPT)
	unknownRandomPT = unknownRandomPT[:unknownRandomPTLen]

	encryptOracle := func(attackerPT []byte) []byte {
		ptLen := len(unknownRandomPT) + len(attackerPT) + len(unknownPT)
		ctLen := crypto.PadLength(ptLen, unknownBlockSize)
		buf := make([]byte, 0, ctLen)
		buf = append(buf, unknownRandomPT...)
		buf = append(buf, attackerPT...)
		buf = append(buf, unknownPT...)
		buf = crypto.Pad(buf[:0], buf[:ptLen], unknownBlockSize)
		enc.CryptBlocks(buf, buf)
		return buf
	}

	// Discover block size and number of padding bytes.
	zero := make([]byte, 64)
	minLen := len(encryptOracle(zero[:0]))
	var blockSize, padding int
	for i := 1; i < len(zero); i++ {
		n := len(encryptOracle(zero[:i]))
		if n > minLen {
			blockSize = n - minLen
			padding = i
			break
		}
	}
	if blockSize == 0 {
		t.Fatal("couldn't discover block size")
	}
	if blockSize != unknownBlockSize {
		t.Fatalf("got block size %d; want %d", blockSize, unknownBlockSize)
	}

	// Discover length of random prefix and unknown plaintext by encrypting
	// two identical blocks with padding bytes before them. When the length of
	// random prefix and padding bytes is a multiple of the block size, we
	// should see the two identical blocks repeat in the ciphertext.
	scratch := make([]byte, 3*blockSize)
	if n, err := rand.Read(scratch[blockSize : 2*blockSize]); err != nil || n < blockSize {
		t.Fatalf("could not generate random block: %v", err)
	}
	copy(scratch[2*blockSize:3*blockSize], scratch[blockSize:2*blockSize])
	var ptLen, randomPTLen, randomPadding int
LenLoop:
	for i := 0; i < blockSize; i++ {
		ct := encryptOracle(scratch[blockSize-i:])
		for j := 0; j+2*blockSize <= len(ct); j += blockSize {
			if bytes.Equal(ct[j:j+blockSize], ct[j+blockSize:j+2*blockSize]) {
				randomPTLen = j - i
				randomPadding = j - randomPTLen
				ptLen = minLen - randomPTLen - padding
				break LenLoop
			}
		}
	}
	if randomPTLen != unknownRandomPTLen {
		t.Fatalf("got random length %d; want %d", randomPTLen, unknownRandomPTLen)
	}
	if ptLen != len(unknownPT) {
		t.Fatalf("got plaintext length %d; want %d", ptLen, len(unknownPT))
	}

	// Encrypt the unknown text with zero prefixes of every length up to the
	// block size. The index indicates the offset within a block of the first
	// unknown plaintext byte. Discard random prefix and padding.
	discard := randomPTLen + randomPadding
	cts := make([][]byte, blockSize)
	for i := range cts {
		cts[i] = encryptOracle(zero[:randomPadding+i])[discard:]
	}

	// Decrypt the plaintext.
	pt := make([]byte, ptLen)
	paddedScratch := make([]byte, randomPadding+blockSize)
	scratch = paddedScratch[randomPadding:]
	for i := 0; i < ptLen; i++ {
		blockIndex := i / blockSize
		byteIndex := i % blockSize

		// Pick a ciphertext such that the first unknown byte is the last byte
		// in the block.
		ct := cts[blockSize-byteIndex-1]
		ctb := ct[blockIndex*blockSize : (blockIndex+1)*blockSize]

		// Try encrypting every possible plaintext block and see what matches.
		found := false
		for j := 0; j < 256 && !found; j++ {
			scratch[blockSize-1] = byte(j)
			db := encryptOracle(paddedScratch)[discard : discard+blockSize]
			if bytes.Equal(db, ctb) {
				found = true
				pt[i] = byte(j)
			}
		}
		if !found {
			t.Fatalf("did not decrypt byte %d", i)
		}

		copy(scratch[:blockSize-1], scratch[1:])
	}

	want := readFile(t, filepath.FromSlash("testdata/s2/p12want.txt"))
	if !bytes.Equal(pt, want) {
		t.Errorf("got:\n%s\nwant:\n%s", pt, want)
	}
}

// PKCS#7 padding validation.
func TestSet2Problem15(t *testing.T) {
	for _, test := range []struct {
		text string
		ok   bool
	}{
		{"", false},
		{"ICE ICE BABY\x04\x04\x04\x04", true},
		{"ICE ICE BABY\x05\x05\x05\x05", false},
		{"ICE ICE BABY\x01\x02\x03\x04", false},
	} {
		buf := []byte(test.text)
		_, err := crypto.Unpad(buf)
		if err == nil && !test.ok {
			t.Errorf("unexpected success: %q", test.text)
		} else if err != nil && test.ok {
			t.Errorf("unexpected failure on %q: %v", test.text, err)
		}
	}
}

// CBC bitflipping attacks
func TestSet2Problem16(t *testing.T) {
	key := make([]byte, 16)
	if n, err := rand.Read(key); err != nil || n < len(key) {
		t.Fatal("could not generate key")
	}
	bs := aes.BlockSize
	iv := make([]byte, bs)
	if n, err := rand.Read(iv); err != nil || n < len(iv) {
		t.Fatal("could not generate initialization vector")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("could not create cipher")
	}
	enc := crypto.NewCBCEncrypter(c, iv)
	dec := crypto.NewCBCDecrypter(c, iv)

	encryptOracle := func(text string) []byte {
		buf := &bytes.Buffer{}
		buf.WriteString("comment1=cooking%20MCs;userdata=")
		text = strings.ReplaceAll(text, "=", "%3D")
		text = strings.ReplaceAll(text, ";", "%3B")
		buf.WriteString(text)
		buf.WriteString(";comment2=%20like%20a%20pound%20of%20bacon")
		data := crypto.Pad(nil, buf.Bytes(), bs)
		enc.CryptBlocks(data, data)
		return data
	}

	adminOracle := func(ct []byte) error {
		pt := make([]byte, len(ct))
		dec.CryptBlocks(pt, ct)
		p := pt
		for {
			i := bytes.IndexByte(p, ';')
			if i < 0 {
				i = len(p)
			}
			if bytes.Equal(p[:i], []byte("admin=true")) {
				return nil
			}
			if i == len(p) {
				return fmt.Errorf("not an admin: %q", p)
			}
			p = p[i+1:]
		}
	}

	// Encrypt a block before the block we want to edit. Content doesn't matter.
	prefixLen := 32
	ct := encryptOracle(strings.Repeat("\x00", bs))
	ctZero := ct[prefixLen : prefixLen+bs]

	// Find the bit difference between the block we want to edit and
	// the block we want to change it to.
	have := []byte(";comment2=%20lik")
	want := []byte(";admin=true;c=ik")
	diff := make([]byte, bs)
	crypto.XOR(diff, have, want)

	// Flip those bits in zero ciphertext block.
	crypto.XOR(ctZero, ctZero, diff)
	if err := adminOracle(ct); err != nil {
		t.Fatal(err)
	}
}
