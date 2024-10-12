package frame

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// 編碼器
type Encoder struct {
	opts options
	w    io.Writer
}

// 創建一個編碼器
func NewEncoder(w io.Writer, opt ...Option) (enc *Encoder, e error) {
	opts := defaultOptions
	for _, o := range opt {
		o.apply(&opts)
	}
	switch opts.id {
	case 8, 16, 32, 64:
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
	enc = &Encoder{
		w:    w,
		opts: opts,
	}
	return
}

// 編碼一個完整的幀
func (enc *Encoder) Encode(id uint64, data []byte) (e error) {
	w, e := enc.NextWriter(id)
	if e != nil {
		return e
	}
	_, e = w.WriteClose(data)
	if e != nil {
		return
	}
	return
}

// 編碼一個完整的幀
func (enc *Encoder) EncodeString(id uint64, data string) (e error) {
	w, e := enc.NextWriter(id)
	if e != nil {
		return e
	}
	_, e = w.WriteClose(StringToBytes(data))
	if e != nil {
		return
	}
	return
}

// 創建一個幀寫入器
func (enc *Encoder) NextWriter(id uint64) (w *FrameWriter, e error) {
	var b []byte
	switch enc.opts.id {
	case 8:
		if id > math.MaxUint8 {
			e = fmt.Errorf(`id invalid %v`, id)
			return
		}
		b = []byte{byte(id)}
	case 16:
		if id > math.MaxUint16 {
			e = fmt.Errorf(`id invalid %v`, id)
			return
		}
		b = make([]byte, 2)
		enc.opts.byteOrder.PutUint16(b, uint16(id))
	case 32:
		if id > math.MaxUint32 {
			e = fmt.Errorf(`id invalid %v`, id)
			return
		}
		b = make([]byte, 4)
		enc.opts.byteOrder.PutUint32(b, uint32(id))
	case 64:
		b = make([]byte, 8)
		enc.opts.byteOrder.PutUint64(b, uint64(id))
	default:
		e = ErrIdBitsInvalid
		return
	}

	w = &FrameWriter{
		id:        b,
		w:         enc.w,
		payload:   enc.opts.payload,
		byteOrder: enc.opts.byteOrder,
	}
	return
}

type FrameWriter struct {
	id        []byte
	w         io.Writer
	payload   int
	byteOrder binary.ByteOrder
}

func write8(w io.Writer, flags byte, b []byte) (n int, e error) {
	var (
		sz      int
		payload = []byte{0}
	)
	for {
		sz = len(b)
		if sz < 125 {
			payload[0] = byte(sz) | flags
			_, e = w.Write(payload)
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		}

		payload[0] = 0x80 | 124
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b[:124])
		n += sz
		if e != nil {
			return
		}
		b = b[124:]
	}
}
func write16(byteOrder binary.ByteOrder, w io.Writer, flags byte, b []byte) (n int, e error) {
	var (
		sz      int
		payload = []byte{0,
			0, 0}
	)
	for {
		sz = len(b)
		if sz < 125 {
			payload[0] = byte(sz) | flags
			_, e = w.Write(payload[:1])
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		} else if sz <= math.MaxUint16 {
			payload[0] = flags | 125
			byteOrder.PutUint16(payload[1:], uint16(sz))
			_, e = w.Write(payload)
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		}

		payload[0] = 0x80 | 125
		byteOrder.PutUint16(payload[1:], uint16(sz))
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b[:math.MaxUint16])
		n += sz
		if e != nil {
			return
		}
		b = b[math.MaxUint16:]
	}
}
func write32(byteOrder binary.ByteOrder, w io.Writer, flags byte, b []byte) (n int, e error) {
	var (
		sz      int
		payload = []byte{0,
			0, 0, 0, 0}
	)
	for {
		sz = len(b)
		if sz < 125 {
			payload[0] = byte(sz) | flags
			_, e = w.Write(payload[:1])
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		} else if sz <= math.MaxUint16 {
			payload[0] = flags | 125
			byteOrder.PutUint16(payload[1:], uint16(sz))
			_, e = w.Write(payload[:3])
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		} else if sz <= math.MaxUint32 {
			payload[0] = flags | 126
			byteOrder.PutUint32(payload[1:], uint32(sz))
			_, e = w.Write(payload)
			if e != nil {
				return
			}
			sz, e = w.Write(b)
			n += sz
			return
		}

		payload[0] = 0x80 | 126
		byteOrder.PutUint32(payload[1:], uint32(sz))
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b[:math.MaxUint32])
		n += sz
		if e != nil {
			return
		}
		b = b[math.MaxUint32:]
	}
}
func write64(byteOrder binary.ByteOrder, w io.Writer, flags byte, b []byte) (sz int, e error) {
	sz = len(b)
	if sz < 125 {
		payload := []byte{flags | byte(sz)}
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b)
		return
	} else if sz <= math.MaxUint16 {
		payload := []byte{flags | 125,
			0, 0}
		byteOrder.PutUint16(payload[1:], uint16(sz))
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b)
		return
	} else if sz <= math.MaxUint32 {
		payload := []byte{flags | 126,
			0, 0, 0, 0}
		byteOrder.PutUint32(payload[1:], uint32(sz))
		_, e = w.Write(payload)
		if e != nil {
			return
		}
		sz, e = w.Write(b)
		return
	}

	payload := []byte{flags | 127,
		0, 0, 0, 0, 0, 0, 0, 0}
	byteOrder.PutUint64(payload[1:], uint64(sz))
	_, e = w.Write(payload)
	if e != nil {
		return
	}
	sz, e = w.Write(b)
	return
}
func (f *FrameWriter) write(end bool, b []byte) (n int, e error) {
	w := f.w
	if w == nil {
		e = ErrFrameWriterExpired
		return
	}
	var flags byte
	if end {
		f.w = nil
	} else {
		flags = 0x80
	}
	id := f.id
	if len(id) != 0 {
		_, e = w.Write(id)
		if e != nil {
			return
		}
		f.id = nil
	}

	switch f.payload {
	case 8:
		n, e = write8(w, flags, b)
	case 16:
		n, e = write16(f.byteOrder, w, flags, b)
	case 32:
		n, e = write32(f.byteOrder, w, flags, b)
	case 64:
		n, e = write64(f.byteOrder, w, flags, b)
	}
	return
}
func (f *FrameWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return f.write(false, b)
}
func (f *FrameWriter) Close() (e error) {
	if f.w == nil {
		e = ErrFrameWriterExpired
	} else {
		if len(f.id) == 0 {
			_, e = f.w.Write([]byte{0})
			if e != nil {
				return
			}
		}
		f.w = nil
	}
	return
}
func (f *FrameWriter) WriteClose(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, f.Close()
	}
	return f.write(true, b)
}
