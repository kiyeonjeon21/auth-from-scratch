package webauthn

// A CBOR decoder covering only what WebAuthn needs (RFC 8949).
//
// WebAuthn hands back two CBOR blobs: the attestation object and, inside it,
// the credential public key as a COSE_Key map. Pulling in a CBOR library would
// hide the one thing worth seeing - that a public key is just a couple of
// integers with labels - so this decodes the subset by hand.
//
// Supported: unsigned/negative ints, byte strings, text strings, arrays, maps.
// Not supported: tags, floats, indefinite-length items. WebAuthn does not use
// them here, and silently accepting things we do not understand is how parsers
// become attack surface.

import (
	"encoding/binary"
	"fmt"
)

type cborReader struct {
	b []byte
	i int
}

func (r *cborReader) byte() (byte, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("CBOR: 데이터가 일찍 끝났다")
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

func (r *cborReader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("CBOR: %d바이트를 읽으려는데 남은 게 부족하다", n)
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out, nil
}

// head reads the major type and its argument.
func (r *cborReader) head() (major byte, arg uint64, err error) {
	c, err := r.byte()
	if err != nil {
		return 0, 0, err
	}
	major = c >> 5
	switch info := c & 0x1f; {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		b, err := r.byte()
		return major, uint64(b), err
	case info == 25:
		b, err := r.take(2)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint16(b)), nil
	case info == 26:
		b, err := r.take(4)
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint32(b)), nil
	case info == 27:
		b, err := r.take(8)
		if err != nil {
			return 0, 0, err
		}
		return major, binary.BigEndian.Uint64(b), nil
	default:
		return 0, 0, fmt.Errorf("CBOR: 지원하지 않는 additional info %d", info)
	}
}

// value decodes one item. Maps come back as map[any]any because COSE_Key uses
// integer labels while the attestation object uses text keys.
func (r *cborReader) value() (any, error) {
	major, arg, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned int
		return int64(arg), nil
	case 1: // negative int: encoded as -1 - arg
		return -1 - int64(arg), nil
	case 2: // byte string
		return r.take(int(arg))
	case 3: // text string
		b, err := r.take(int(arg))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4: // array
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := r.value()
			if err != nil {
				return nil, err
			}
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7: // simple values: only false/true/null are expected
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
	}
	return nil, fmt.Errorf("CBOR: 지원하지 않는 major type %d", major)
}

// cborDecodeFirst decodes one item and reports how many bytes it consumed.
// The attestation object is followed by nothing, but authData inside it is
// followed by extensions, so the caller needs the offset.
func cborDecodeFirst(b []byte) (any, int, error) {
	r := &cborReader{b: b}
	v, err := r.value()
	if err != nil {
		return nil, 0, err
	}
	return v, r.i, nil
}
