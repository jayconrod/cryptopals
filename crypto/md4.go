// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copied from golang.org/x/crypto/md4

// Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
//
// Deprecated: MD4 is cryptographically broken and should should only be used
// where compatibility with legacy systems, not security, is the goal. Instead,
// use a secure hash like SHA-256 (from crypto/sha256).
package crypto

import (
	"encoding/binary"
)

// The size of an MD4 checksum in bytes.
const MD4Size = 16

// The blocksize of MD4 in bytes.
const MD4BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// MD4 represents the partial evaluation of a checksum.
type MD4 struct {
	S   [4]uint32
	X   [_Chunk]byte
	NX  int
	Len uint64
}

func (d *MD4) Reset() {
	d.S[0] = _Init0
	d.S[1] = _Init1
	d.S[2] = _Init2
	d.S[3] = _Init3
	d.NX = 0
	d.Len = 0
}

// Get returns the state of d. Like Sum but does not append padding first.
// May only be called on a 64-byte boundary.
func (d *MD4) Get() (uint64, [MD4Size]byte) {
	if d.NX != 0 {
		panic("d.NX != 0")
	}

	var h [MD4Size]byte
	for i, s := range d.S {
		binary.LittleEndian.PutUint32(h[i*4:(i+1)*4], s)
	}
	return d.Len, h
}

// Set sets the state of d.
func (d *MD4) Set(n uint64, h [MD4Size]byte) {
	for i := range d.S {
		d.S[i] = binary.LittleEndian.Uint32(h[i*4 : (i+1)*4])
	}
	if n%64 != 0 {
		panic("n % 64 != 0")
	}
	d.NX = 0
	d.Len = n
}

// NewMD4 returns a new hash.Hash computing the MD4 checksum.
func NewMD4() *MD4 {
	d := new(MD4)
	d.Reset()
	return d
}

func (d *MD4) Size() int { return MD4Size }

func (d *MD4) BlockSize() int { return MD4BlockSize }

func (d *MD4) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.Len += uint64(nn)
	if d.NX > 0 {
		n := len(p)
		if n > _Chunk-d.NX {
			n = _Chunk - d.NX
		}
		for i := 0; i < n; i++ {
			d.X[d.NX+i] = p[i]
		}
		d.NX += n
		if d.NX == _Chunk {
			_Block(d, d.X[0:])
			d.NX = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.NX = copy(d.X[:], p)
	}
	return
}

func (d0 *MD4) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(MD4)
	*d = *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	len := d.Len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.NX != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.S {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

func MD4Sum(data []byte) [MD4Size]byte {
	d := NewMD4()
	d.Write(data)
	var sum [MD4Size]byte
	d.Sum(sum[:0])
	return sum
}
