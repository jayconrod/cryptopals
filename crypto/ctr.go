package crypto

import (
	"crypto/cipher"
	"fmt"
	"math"
	"unsafe"
)

type CTRStream struct {
	block cipher.Block

	// in is the next block that, when encrypted, becomes the keystream.
	// It is initialized with iv and is incremented for each block.
	in []byte

	// low and high are pointers to 64-bit words of in. They are used to
	// increment in, which is effectively a 128-bit integer.
	low, high *uint64

	// out is the next keystream block.
	out []byte

	// off is the number of bytes in out that have been consumed.
	off int
}

func NewCTR(block cipher.Block, iv []byte) *CTRStream {
	bs := block.BlockSize()
	if bs != 16 {
		panic(fmt.Sprintf("block.BlockSize() is %d; must be 16", bs))
	}
	if len(iv) != bs {
		panic(fmt.Sprintf("len(iv) is %d; must be %d", len(iv), bs))
	}
	in := make([]byte, bs)
	copy(in, iv)
	cs := &CTRStream{
		block: block,
		in:    in,
		low:   (*uint64)(unsafe.Pointer(&in[8])),
		high:  (*uint64)(unsafe.Pointer(&in[0])),
		out:   make([]byte, bs),
		off:   0,
	}
	cs.block.Encrypt(cs.out, cs.in)
	return cs
}

func (cs *CTRStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("len(dst) (%d) less than len(src) (%d)", len(dst), len(src)))
	}

	bs := len(cs.in)
	for len(src) > 0 {
		if cs.off == bs {
			cs.next()
		}
		n := bs - cs.off
		if len(src) < n {
			n = len(src)
		}
		XOR(dst[:n], src[:n], cs.out[cs.off:cs.off+n])
		dst = dst[n:]
		src = src[n:]
		cs.off += n
	}
}

func (cs *CTRStream) Seek(offset int) {
	if offset < 0 {
		panic(fmt.Sprintf("cannot seek backward with offset %d", offset))
	}
	bs := len(cs.in)
	if offset <= bs-cs.off {
		cs.off += offset
		return
	}
	if cs.off > 0 {
		offset -= bs - cs.off
		cs.add(1)
		cs.off = 0
	}
	cs.add(uint64(offset / bs))
	cs.off = offset % bs
	cs.block.Encrypt(cs.out, cs.in)
}

func (cs *CTRStream) next() {
	cs.add(1)
	cs.off = 0
	cs.block.Encrypt(cs.out, cs.in)
}

func (cs *CTRStream) add(n uint64) {
	if n > math.MaxUint64-*cs.low {
		*cs.high++
	}
	*cs.low += n
}
