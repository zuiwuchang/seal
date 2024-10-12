package frame

import (
	"encoding/binary"
	"io"
)

// 解析器
type Decoder struct {
	opts options
	r    io.Reader
}

// 創建一個解碼器
func NewDecoder(r io.Reader, opt ...Option) (dec *Decoder, e error) {
	opts := defaultOptions
	for _, o := range opt {
		o.apply(&opts)
	}
	switch opts.id {
	case 0, 8, 16, 32, 64:
	default:
		e = ErrIdBitsInvalid
		return
	}
	switch opts.payload {
	case 8, 16, 32, 64:
	default:
		e = ErrPayloadBitsInvalid
		return
	}
	dec = &Decoder{
		r:    r,
		opts: opts,
	}
	return
}
func (dec *Decoder) Decode() (id uint64, data []byte, e error) {
	id, r, e := dec.NextReader()
	if e != nil {
		return
	}
	data, e = io.ReadAll(r)
	return
}

// 創建一個幀讀取器
func (dec *Decoder) NextReader() (id uint64, r *FrameReader, e error) {
	switch dec.opts.id {
	case 0:
	case 8:
		buf := []byte{0}
		_, e = io.ReadAtLeast(dec.r, buf, len(buf))
		if e != nil {
			return
		}
		id = uint64(buf[0])
	case 16:
		buf := []byte{0, 0}
		_, e = io.ReadAtLeast(dec.r, buf, len(buf))
		if e != nil {
			return
		}
		id = uint64(dec.opts.byteOrder.Uint16(buf))
	case 32:
		buf := []byte{0, 0, 0, 0}
		_, e = io.ReadAtLeast(dec.r, buf, len(buf))
		if e != nil {
			return
		}
		id = uint64(dec.opts.byteOrder.Uint32(buf))
	case 64:
		buf := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		_, e = io.ReadAtLeast(dec.r, buf, len(buf))
		if e != nil {
			return
		}
		id = dec.opts.byteOrder.Uint64(buf)
	default:
		e = ErrIdBitsInvalid
		return
	}

	r = &FrameReader{
		r:         dec.r,
		payload:   dec.opts.payload,
		buf:       make([]byte, 8),
		byteOrder: dec.opts.byteOrder,
	}
	if dec.opts.id == 0 {
		e = r.readSize(dec.r, true)
		if e != nil {
			return
		}
	}
	return
}

type FrameReader struct {
	r         io.Reader
	payload   int
	size      uint64
	end       bool
	buf       []byte
	byteOrder binary.ByteOrder
}

func (f *FrameReader) readSize(r io.Reader, zero bool) (e error) {
	for f.size == 0 && !f.end {
		_, e = io.ReadAtLeast(r, f.buf[:1], 1)
		if e != nil {
			if e == io.EOF {
				if !zero {
					e = io.ErrUnexpectedEOF
				}
			}
			return
		}

		flags := f.buf[0] & 0x80
		if flags == 0 {
			f.end = true
			flags = f.buf[0]
		} else {
			flags = f.buf[0] & 0x7F
		}
		if flags < 125 {
			f.size = uint64(flags)
		} else {
			switch flags {
			case 125:
				if f.payload < 16 {
					e = ErrFramePayloadLengthInvalid
					return
				}
				_, e = io.ReadAtLeast(r, f.buf[:2], 2)
				if e != nil {
					if e == io.EOF {
						e = io.ErrUnexpectedEOF
					}
					return
				}
				f.size = uint64(f.byteOrder.Uint16(f.buf))
			case 126:
				if f.payload < 32 {
					e = ErrFramePayloadLengthInvalid
					return
				}
				_, e = io.ReadAtLeast(r, f.buf[:4], 4)
				if e != nil {
					if e == io.EOF {
						e = io.ErrUnexpectedEOF
					}
					return
				}
				f.size = uint64(f.byteOrder.Uint32(f.buf))
			case 127:
				if f.payload < 64 {
					e = ErrFramePayloadLengthInvalid
					return
				}
				_, e = io.ReadAtLeast(r, f.buf[:8], 8)
				if e != nil {
					if e == io.EOF {
						e = io.ErrUnexpectedEOF
					}
					return
				}
				f.size = f.byteOrder.Uint64(f.buf)
			}
		}
	}
	return
}
func (f *FrameReader) Read(b []byte) (n int, e error) {
	max := len(b)
	if max == 0 {
		return
	}
	r := f.r
	if r == nil {
		e = io.EOF
		return
	}
	e = f.readSize(r, false)
	if e != nil {
		return
	}

	if uint64(max) > f.size {
		max = int(f.size)
	}
	if max != 0 {
		n, e = io.ReadAtLeast(r, b[:max], max)
		if n != 0 {
			f.size -= uint64(n)
		}
	}
	if f.end && f.size == 0 {
		f.r = nil
		if n == 0 {
			if e == nil {
				e = io.EOF
			}
		}
	}
	return
}
