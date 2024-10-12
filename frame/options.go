package frame

import (
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

var ErrIdInvalid = errors.New(`ID Invalid`)

func WriteString(w io.Writer, id uint8, data string) (uint64, error) {
	return Write(w, id, StringToBytes(data))
}

// id + [sz + data]...
func Write(w io.Writer, id uint8, data []byte) (n uint64, e error) {
	sz := len(data)
	if sz == 0 {
		return
	}
	return
}

var defaultOptions = options{
	id:        32,
	payload:   32,
	byteOrder: binary.BigEndian,
}

type Option interface {
	apply(*options)
}
type options struct {
	id        int
	payload   int
	byteOrder binary.ByteOrder
}
type funcOption struct {
	f func(*options)
}

func (fdo *funcOption) apply(do *options) {
	fdo.f(do)
}
func newFuncOption(f func(*options)) *funcOption {
	return &funcOption{
		f: f,
	}
}

// Set the length of bytes occupied by id
func WithId(bits int) Option {
	return newFuncOption(func(o *options) {
		o.id = bits
	})
}

// Set the length of bytes occupied by payload
func WithPayload(bits int) Option {
	return newFuncOption(func(o *options) {
		o.payload = bits
	})
}

// Set byteOrder
func WithByteOrder(byteOrder binary.ByteOrder) Option {
	return newFuncOption(func(o *options) {
		if byteOrder == nil {
			o.byteOrder = binary.BigEndian
		} else {
			o.byteOrder = byteOrder
		}
	})
}
