package crypto

import (
	"crypto/cipher"
	"fmt"
	"math"
	"math/bits"
	"sort"
)

func XOR(buf, x, y []byte) []byte {
	if len(x) != len(y) {
		panic(fmt.Sprintf("buffers have different length: len(x) = %d, len(y) = %d", len(x), len(y)))
	}
	n := len(x)
	if cap(buf) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	for i := range x {
		buf[i] = x[i] ^ y[i]
	}
	return buf
}

func XORByte(buf, x []byte, y byte) []byte {
	n := len(x)
	if cap(buf) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	for i, b := range x {
		buf[i] = b ^ y
	}
	return buf
}

func XORRepeat(buf, x, y []byte) []byte {
	n := len(x)
	if cap(buf) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	for i, b := range x {
		buf[i] = b ^ y[i%len(y)]
	}
	return buf
}

func CrackXORByte(ct []byte) (key byte, score float64, pt []byte) {
	bestScore := math.Inf(1.)
	var bestKey byte
	var freqs []float64
	for key := 0; key < 256; key++ {
		pt = XORByte(pt, ct, byte(key))
		freqs = ByteFrequency(freqs, pt)
		score := Norm(freqs, EnglishFreqs[:])
		if score < bestScore {
			bestScore = score
			bestKey = byte(key)
		}
	}
	return bestKey, bestScore, XORByte(pt, ct, bestKey)
}

func CrackXORRepeat(ct []byte, minKeySize, maxKeySize int) (key, pt []byte, err error) {
	minBlocks := 4
	if len(ct) < minBlocks*minKeySize {
		return nil, nil, fmt.Errorf("ciphertext has length %d, need %d bytes (2x minimum key size)", len(ct), 2*minKeySize)
	}
	if len(ct) < minBlocks*maxKeySize {
		maxKeySize = len(ct) / minBlocks
	}

	type attempt struct {
		keySize int
		dist    float64
		score   float64
		key     []byte
	}
	attempts := make([]attempt, maxKeySize-minKeySize)
	for i := range attempts {
		sz := minKeySize + i
		attempts[i].keySize = sz
		for j := 0; j < minBlocks-1; j++ {
			attempts[i].dist += float64(HammingDistance(ct[j*sz:(j+1)*sz], ct[(j+1)*sz:(j+2)*sz]))
		}
		attempts[i].dist /= float64(sz)
	}
	sort.Slice(attempts, func(i, j int) bool {
		return attempts[i].dist < attempts[j].dist
	})

	crackWithKeySize := func(keySize int) (key []byte, score float64) {
		transpose := make([][]byte, keySize)
		for i, b := range ct {
			k := i % keySize
			transpose[k] = append(transpose[k], b)
		}
		key = make([]byte, keySize)
		for i := 0; i < keySize; i++ {
			var byteScore float64
			key[i], byteScore, _ = CrackXORByte(transpose[i])
			score += byteScore
		}
		score /= float64(keySize)
		return key, score
	}

	if len(attempts) > 5 {
		attempts = attempts[:5]
	}
	for i := range attempts {
		attempts[i].key, attempts[i].score = crackWithKeySize(attempts[i].keySize)
	}
	bestScore := math.Inf(1)
	var bestKey []byte
	for i := range attempts {
		if attempts[i].score < bestScore {
			bestScore = attempts[i].score
			bestKey = attempts[i].key
		}
	}

	pt = XORRepeat(nil, ct, bestKey)
	return bestKey, pt, nil
}

func ByteFrequency(freqs []float64, x []byte) []float64 {
	counts := make([]int, 256)
	for _, b := range x {
		counts[int(b)]++
	}

	if len(freqs) < 256 {
		freqs = make([]float64, 256)
	} else {
		freqs = freqs[:256]
	}
	for i, c := range counts {
		freqs[i] = float64(c) / float64(len(x))
	}
	return freqs
}

func Norm(x, y []float64) float64 {
	if len(x) != len(y) {
		panic(fmt.Sprintf("buffers have different length: len(x) = %d, len(y) = %d", len(x), len(y)))
	}
	e := 0.
	for i := range x {
		e += math.Abs(x[i] - y[i])
	}
	e /= float64(len(x))
	return e
}

func HammingDistance(x, y []byte) int {
	if len(x) != len(y) {
		panic(fmt.Sprintf("buffers have different length: len(x) = %d, len(y) = %d", len(x), len(y)))
	}
	n := 0
	for i := range x {
		b := x[i] ^ y[i]
		n += bits.OnesCount8(uint8(b))
	}
	return n
}

type ecbCrypter struct {
	blockSize int
	crypt     func(dst, src []byte)
}

func NewECBEncrypter(c cipher.Block) cipher.BlockMode {
	return &ecbCrypter{
		blockSize: c.BlockSize(),
		crypt:     c.Encrypt,
	}
}

func NewECBDecrypter(c cipher.Block) cipher.BlockMode {
	return &ecbCrypter{
		blockSize: c.BlockSize(),
		crypt:     c.Decrypt,
	}
}

func (cr *ecbCrypter) BlockSize() int {
	return cr.blockSize
}

func (cr *ecbCrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("dst is shorter than src: len(dst) = %d, len(src) = %d", dst, src))
	}
	n := len(src)
	bs := cr.blockSize
	if n%bs != 0 {
		panic(fmt.Sprintf("src not a multiple of block size: len(src) = %d, block size = %d", n, bs))
	}

	for i := 0; i < n; i += bs {
		cr.crypt(dst[i:i+bs], src[i:i+bs])
	}
}

func DetectECB(ct []byte) bool {
	blockSize := 16
	if len(ct)%blockSize != 0 {
		panic(fmt.Sprintf("ciphertext length (%d) not a multiple of block size", len(ct)))
	}
	blocks := make(map[string]struct{})
	s := string(ct)
	for len(s) > 0 {
		b := s[:blockSize]
		s = s[blockSize:]
		if _, ok := blocks[b]; ok {
			return true
		}
		blocks[b] = struct{}{}
	}
	return false
}
