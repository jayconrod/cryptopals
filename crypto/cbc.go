package crypto

import (
	"crypto/cipher"
	"fmt"
)

type cbcEncrypter struct {
	c  cipher.Block
	cb []byte
}

func NewCBCEncrypter(c cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != c.BlockSize() {
		panic(fmt.Sprintf("iv length is not block size: len(iv) = %d, block size = %d", len(iv), c.BlockSize()))
	}
	return &cbcEncrypter{
		c:  c,
		cb: iv,
	}
}

func (cr *cbcEncrypter) BlockSize() int {
	return cr.c.BlockSize()
}

func (cr *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("dst is shorter than src: len(dst) = %d, len(src) = %d", len(dst), len(src)))
	}
	n := len(src)
	bs := cr.c.BlockSize()
	if n%bs != 0 {
		panic(fmt.Sprintf("src not a multiple of block size: len(src) = %d, block size = %d", len(src), bs))
	}

	tmp := make([]byte, bs)
	for i := 0; i < n; i += bs {
		sb := src[i : i+bs]
		XOR(tmp, sb, cr.cb)
		db := dst[i : i+bs]
		cr.c.Encrypt(db, tmp)
		cr.cb = db
	}
}

type cbcDecrypter struct {
	c  cipher.Block
	cb []byte
}

func NewCBCDecrypter(c cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != c.BlockSize() {
		panic(fmt.Sprintf("iv length is not block size: len(iv) = %d, block size = %d", len(iv), c.BlockSize()))
	}
	return &cbcDecrypter{
		c:  c,
		cb: iv,
	}
}

func (cr *cbcDecrypter) BlockSize() int {
	return cr.c.BlockSize()
}

func (cr *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("dst is shorter than src: len(dst) = %d, len(src) = %d", len(dst), len(src)))
	}
	n := len(src)
	bs := cr.c.BlockSize()
	if n%bs != 0 {
		panic(fmt.Sprintf("src not a multiple of block size: len(src) = %d, block size = %d", len(src), bs))
	}

	dec := make([]byte, bs)
	for i := 0; i < len(src); i += bs {
		sb := src[i : i+bs]
		cr.c.Decrypt(dec, sb)
		db := dst[i : i+bs]
		XOR(db, dec, cr.cb)
		cr.cb = sb
	}
}
