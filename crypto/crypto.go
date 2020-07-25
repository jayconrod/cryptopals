package crypto

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
)

func XOR(dst, x, y []byte) {
	if len(x) != len(y) {
		panic(fmt.Sprintf("buffers have different length: len(x) = %d, len(y) = %d", len(x), len(y)))
	}
	if len(dst) < len(x) {
		panic(fmt.Sprintf("dst is too short: len(dst) = %d, len(x) = %d", len(dst), len(x)))
	}
	for i := range x {
		dst[i] = x[i] ^ y[i]
	}
}

func XORByte(dst, x []byte, y byte) {
	for i := range x {
		dst[i] = x[i] ^ y
	}
}

func XORRepeat(dst, x, y []byte) {
	for i := range x {
		dst[i] = x[i] ^ y[i%len(y)]
	}
}

func CrackXORByte(ct []byte) (key byte, score float64, pt []byte) {
	pt = make([]byte, len(ct))
	bestScore := math.Inf(1.)
	var bestKey byte
	var freqs []float64
	for key := 0; key < 256; key++ {
		XORByte(pt, ct, byte(key))
		freqs = ByteFrequency(freqs, pt)
		score := Norm(freqs, EnglishFreqs[:])
		if score < bestScore {
			bestScore = score
			bestKey = byte(key)
		}
	}
	XORByte(pt, ct, bestKey)
	return bestKey, bestScore, pt
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

	pt = make([]byte, len(ct))
	XORRepeat(pt, ct, bestKey)
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

func PadLength(srcLen, blockSize int) int {
	return srcLen + (blockSize - (srcLen % blockSize))
}

// Pad appends src to dst, appends PKCS#7 padding bytes at the end, and returns
// the resulting slice. The number of bytes appended to dst will be a multiple
// of blockSize.
func Pad(dst, src []byte, blockSize int) []byte {
	b := blockSize - (len(src) % blockSize)
	padLen := len(src) + b
	if cap(dst) >= len(dst)+padLen &&
		(len(src) == 0 || &dst[:len(dst)+1][len(dst)] == &src[0]) {
		// src is right after dst in the same storage, and there's enough room to
		// append the padding bytes without reallocating. Just increase len(dst).
		dst = dst[:len(dst)+len(src)]
	} else if cap(dst) >= len(dst)+padLen {
		// dst has enough room to contain everything. Don't reallocate.
		dst = append(dst, src...)
	} else {
		// dst is too short. Reallocate and copy both dst and src.
		buf := make([]byte, 0, len(dst)+padLen)
		dst = append(buf, dst...)
		dst = append(dst, src...)
	}

	for i := 0; i < b; i++ {
		dst = append(dst, byte(b))
	}
	return dst
}

// Unpad returns a slice of src, removing PKCS#7 padding bytes at the end.
func Unpad(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("can't remove padding from empty text")
	}
	b := int(src[len(src)-1])
	if b == 0 || b > len(src) {
		return nil, errors.New("invalid padding")
	}
	unpadLen := len(src) - b
	for i := unpadLen; i < len(src); i++ {
		if src[i] != byte(b) {
			return nil, errors.New("invalid padding")
		}
	}
	return src[:unpadLen], nil
}

// slicesOverlap returns true if appending src to dst would have no effect.
// This is true if src and dst point to the same storage, len(dst) is 0,
// and cap(dst) is at least len(src).
func slicesOverlap(dst, src []byte) bool {
	return len(src) > 0 && cap(dst) >= len(src) && &dst[:1][0] == &src[0]
}
