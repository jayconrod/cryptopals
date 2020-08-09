package crypto

import (
	"encoding/binary"
)

// The size of a SHA-1 checksum in bytes.
const SHA1Size = 20

// The blocksize of SHA-1 in bytes.
const SHA1BlockSize = 64

const (
	SHA1Chunk = 64
	SHA1Init0 = 0x67452301
	SHA1Init1 = 0xEFCDAB89
	SHA1Init2 = 0x98BADCFE
	SHA1Init3 = 0x10325476
	SHA1Init4 = 0xC3D2E1F0
)

// SHA1 represents the partial evaluation of a checksum.
type SHA1 struct {
	H   [5]uint32
	X   [SHA1Chunk]byte
	NX  int
	Len uint64
}

const (
	SHA1Magic     = "sha\x01"
	marshaledSize = len(SHA1Magic) + 5*4 + SHA1Chunk + 8
)

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func (d *SHA1) Reset() {
	d.H[0] = SHA1Init0
	d.H[1] = SHA1Init1
	d.H[2] = SHA1Init2
	d.H[3] = SHA1Init3
	d.H[4] = SHA1Init4
	d.NX = 0
	d.Len = 0
}

// New returns a new hash.Hash computing the SHA1 checksum. The Hash also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to
// marshal and unmarshal the internal state of the hash.
func New() *SHA1 {
	d := new(SHA1)
	d.Reset()
	return d
}

func (d *SHA1) Size() int { return SHA1Size }

func (d *SHA1) BlockSize() int { return SHA1BlockSize }

func (d *SHA1) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.Len += uint64(nn)
	if d.NX > 0 {
		n := copy(d.X[d.NX:], p)
		d.NX += n
		if d.NX == SHA1Chunk {
			block(d, d.X[:])
			d.NX = 0
		}
		p = p[n:]
	}
	if len(p) >= SHA1Chunk {
		n := len(p) &^ (SHA1Chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.NX = copy(d.X[:], p)
	}
	return
}

func (d *SHA1) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *SHA1) checkSum() [SHA1Size]byte {
	len := d.Len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.NX != 0 {
		panic("d.nx != 0")
	}

	var digest [SHA1Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.H[0])
	binary.BigEndian.PutUint32(digest[4:], d.H[1])
	binary.BigEndian.PutUint32(digest[8:], d.H[2])
	binary.BigEndian.PutUint32(digest[12:], d.H[3])
	binary.BigEndian.PutUint32(digest[16:], d.H[4])

	return digest
}

// SHA1Sum returns the SHA-1 checksum of the data.
func SHA1Sum(data []byte) [SHA1Size]byte {
	var d SHA1
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
