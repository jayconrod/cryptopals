package crypto

import (
	"crypto/cipher"
	"fmt"
	"unsafe"
)

type ctrStream struct {
	block   cipher.Block
	in, out []byte
	n       *uint64
	off     int
}

func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	bs := block.BlockSize()
	if bs != 16 {
		panic(fmt.Sprintf("block.BlockSize() is %d; must be 16", bs))
	}
	if len(iv) != bs {
		panic(fmt.Sprintf("len(iv) is %d; must be %d", len(iv), bs))
	}
	cs := &ctrStream{
		block: block,
		in:    iv,
		out:   make([]byte, bs),
		n:     (*uint64)(unsafe.Pointer(&iv[8])),
	}
	cs.next()
	return cs
}

func (cs *ctrStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("len(dst) (%d) less than len(src) (%d)", len(dst), len(src)))
	}

	bs := len(cs.in)
	for len(src) > 0 {
		n := bs - cs.off
		if len(src) < n {
			n = len(src)
		}
		XOR(dst[:n], src[:n], cs.out[cs.off:cs.off+n])
		dst = dst[n:]
		src = src[n:]
		cs.off += n
		if cs.off == bs {
			cs.next()
		}
	}
}

func (cs *ctrStream) next() {
	cs.block.Encrypt(cs.out, cs.in)
	(*cs.n)++
	cs.off = 0
}
