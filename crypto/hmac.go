package crypto

import "hash"

type hmac struct {
	inner, outer hash.Hash
	k            []byte
}

func NewHMAC(newH func() hash.Hash, key []byte) hash.Hash {
	inner := newH()
	outer := newH()

	bs := inner.BlockSize()
	k := make([]byte, bs)
	if len(key) <= bs {
		copy(k, key)
	} else {
		kh := newH()
		kh.Write(key)
		kh.Sum(k[:0])
	}

	hmac := &hmac{inner: inner, outer: outer, k: k}
	hmac.Reset()
	return hmac
}

func (hmac *hmac) Write(b []byte) (int, error) {
	return hmac.inner.Write(b)
}

func (hmac *hmac) Sum(b []byte) []byte {
	bLen := len(b)
	b2 := hmac.inner.Sum(b)
	innerHash := b2[bLen:]

	bs := len(hmac.k)
	block := make([]byte, bs)
	XORByte(block, hmac.k, 0x5c)
	hmac.outer.Write(block)
	hmac.outer.Write(innerHash)
	return hmac.outer.Sum(b)
}

func (hmac *hmac) Reset() {
	hmac.inner.Reset()
	hmac.outer.Reset()

	bs := len(hmac.k)
	block := make([]byte, bs)
	XORByte(block, hmac.k, 0x36)
	hmac.inner.Write(block)
}

func (hmac *hmac) Size() int {
	return hmac.inner.Size()
}

func (hmac *hmac) BlockSize() int {
	return hmac.inner.BlockSize()
}
