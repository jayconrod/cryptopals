package crypto

import (
	"crypto/cipher"
	"fmt"
)

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
	for i := 0; i < len(ct); i += blockSize {
		b := s[i : i+blockSize]
		if _, ok := blocks[b]; ok {
			return true
		}
		blocks[b] = struct{}{}
	}
	return false
}
