package crypto

import (
	"fmt"
)

type MT19937 struct {
	MT    [n]uint32
	Index int
}

const (
	w = 32
	n = 624
	m = 397
	r = 31
	a = 0x9908B0DF
	u = 11
	d = 0xFFFFFFFF
	s = 7
	b = 0x9D2C5680
	t = 15
	c = 0xEFC60000
	l = 18
	f = 1812433253

	lowerMask uint32 = (1 << r) - 1
	upperMask uint32 = ^lowerMask
)

func NewMT19937() *MT19937 {
	return &MT19937{Index: n + 1}
}

func (src *MT19937) Seed(seed uint32) {
	src.Index = n
	src.MT[0] = seed
	for i := 1; i < n; i++ {
		src.MT[i] = f*(src.MT[i-1]^(src.MT[i-1]>>(w-2))) + uint32(i)
	}
}

func (src *MT19937) Uint32() uint32 {
	if src.Index >= n {
		if src.Index > n {
			panic("generator was never seeded")
		}
		src.twist()
	}

	y := src.MT[src.Index]
	y ^= (y >> u) & d
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= y >> l
	src.Index++
	return y
}

func (src *MT19937) twist() {
	for i := 0; i < n; i++ {
		x := src.MT[i]&upperMask + src.MT[(i+1)%n]&lowerMask
		xA := x >> 1
		if x%2 != 0 {
			xA ^= a
		}
		src.MT[i] = src.MT[(i+m)%n] ^ xA
	}
	src.Index = 0
}

type mt19937Stream struct {
	src  MT19937
	w, b uint32
}

func NewMT19937Stream(seed uint32) *mt19937Stream {
	src := NewMT19937()
	src.Seed(seed)
	return &mt19937Stream{src: *src}
}

func (ms *mt19937Stream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Sprintf("len(dst) (%d) less than len(src) (%d)", len(dst), len(src)))
	}

	for i := 0; i < len(dst); i++ {
		if ms.b == 0 {
			ms.w = ms.src.Uint32()
			ms.b = 4
		}
		dst[i] = src[i] ^ byte(ms.w)
		ms.w >>= 8
		ms.b--
	}
}
