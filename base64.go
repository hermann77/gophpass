package main

import (
    "encoding/base64"
)

// MyEncoding is Alias/Composition of struct Encoding
type MyEncoding struct {
    base64.Encoding		// extend base64.Encoding because 
    encode    [64]byte
    decodeMap [256]byte
    padChar   rune
}

const (
	StdPadding rune = '=' // Standard padding character
	NoPadding  rune = -1  // No padding
)

// a string for mapping an int to the corresponding base 64 character.
const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var bcEncoding = base64.NewEncoding(alphabet)


func base64Encode(src []byte) []byte {
    n := bcEncoding.EncodedLen(len(src))
    dst := make([]byte, n)

    MyNewEncoding(alphabet).MyEncode(dst, src)
    return dst
}

// MyEncode is overridden methode base64.Encoding.Encode() (polymorphism) 
// MyEncoding is a Composition class of Encoding
func (enc *MyEncoding) MyEncode(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	// enc is a pointer receiver, so the use of enc.encode within the hot
	// loop below means a nil check at every operation. Lift that nil check
	// outside of the loop to speed up the encoder.
    _ = enc.encode

	di, si := 0, 0
    n := (len(src) / 3) * 3
        
	for si < n {
		// Convert 3x 8bit source bytes into 4 bytes
		// val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
        val := uint(src[si+0]) | uint(src[si+1])<<8 | uint(src[si+2])<<16

        dst[di+0] = enc.encode[val&0x3F] 
		dst[di+1] = enc.encode[val>>6&0x3F]
		dst[di+2] = enc.encode[val>>12&0x3F]
		dst[di+3] = enc.encode[val>>18&0x3F]

		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}
	// Add the remaining small block
	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = enc.encode[val>>18&0x3F]
	dst[di+1] = enc.encode[val>>12&0x3F]

	switch remain {
	case 2:
		dst[di+2] = enc.encode[val>>6&0x3F]
		if enc.padChar != NoPadding {
			dst[di+3] = byte(enc.padChar)
		}
	case 1:
		if enc.padChar != NoPadding {
			dst[di+2] = byte(enc.padChar)
			dst[di+3] = byte(enc.padChar)
		}
	}
}

// MyNewEncoding overrides base64.Encoding.NewEncoding()
func MyNewEncoding(encoder string) *MyEncoding {
	if len(encoder) != 64 {
		panic("encoding alphabet is not 64-bytes long")
	}
	for i := 0; i < len(encoder); i++ {
		if encoder[i] == '\n' || encoder[i] == '\r' {
			panic("encoding alphabet contains newline character")
		}
	}

	e := new(MyEncoding)
	e.padChar = StdPadding
	copy(e.encode[:], encoder)

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e
}
