package frame

import (
	"bytes"
	"encoding/binary"

	"github.com/zuiwuchang/seal/raw"
)

const (
	Metadata     = 1
	PrivateChain = 2
	PublicChain  = 3
	PublicKey    = 4
)

func MarshalMetadata(m *raw.Metadata) (b []byte, e error) {
	var buf bytes.Buffer
	e = buf.WriteByte(Metadata)
	if e != nil {
		return
	}

	w, e := NewEncoder(&buf, WithId(8), WithPayload(32))
	if e != nil {
		return
	}

	if len(m.Hash) != 0 {
		e = w.EncodeString(1, m.Hash)
		if e != nil {
			return
		}
	}
	if len(m.Parent) != 0 {
		e = w.Encode(2, m.Parent)
		if e != nil {
			return
		}
	}
	if len(m.PublicKey) != 0 {
		e = w.Encode(3, m.PublicKey)
		if e != nil {
			return
		}
	}
	if m.Afrer > 0 {
		t := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(m.Afrer))
		e = w.Encode(4, t)
		if e != nil {
			return
		}
	}
	if m.Before > 0 {
		t := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(m.Before))
		e = w.Encode(5, t)
		if e != nil {
			return
		}
	}

	if len(m.Country) != 0 {
		e = w.EncodeString(6, m.Country)
		if e != nil {
			return
		}
	}
	if len(m.State) != 0 {
		e = w.EncodeString(7, m.State)
		if e != nil {
			return
		}
	}
	if len(m.Locality) != 0 {
		e = w.EncodeString(8, m.Locality)
		if e != nil {
			return
		}
	}
	if len(m.Organization) != 0 {
		e = w.EncodeString(9, m.Organization)
		if e != nil {
			return
		}
	}
	if len(m.Organizational) != 0 {
		e = w.EncodeString(9, m.Organizational)
		if e != nil {
			return
		}
	}
	if len(m.Content) != 0 {
		e = w.Encode(11, m.Content)
		if e != nil {
			return
		}
	}

	b = buf.Bytes()
	return
}
func MarshalPrivateChain(m *raw.PrivateChain) (b []byte, e error) {
	var buf bytes.Buffer
	e = buf.WriteByte(PrivateChain)
	if e != nil {
		return
	}
	w, e := NewEncoder(&buf, WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	if len(m.PublicChain) != 0 {
		e = w.Encode(1, m.PublicChain)
		if e != nil {
			return
		}
	}
	if len(m.PrivateKey) != 0 {
		e = w.Encode(2, m.PrivateKey)
		if e != nil {
			return
		}
	}
	b = buf.Bytes()
	return
}
func MarshalPublicChain(m *raw.PublicChain) (b []byte, e error) {
	var buf bytes.Buffer
	e = buf.WriteByte(PublicChain)
	if e != nil {
		return
	}
	w, e := NewEncoder(&buf, WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	if len(m.Parent) != 0 {
		e = w.Encode(1, m.Parent)
		if e != nil {
			return
		}
	}
	if m.PublicKey != nil {
		var pub []byte
		pub, e = MarshalPublicKey(m.PublicKey)
		if e != nil {
			return
		}
		e = w.Encode(2, pub)
		if e != nil {
			return
		}
	}
	b = buf.Bytes()
	return
}
func MarshalPublicKey(m *raw.PublicKey) (b []byte, e error) {
	var buf bytes.Buffer
	e = buf.WriteByte(PublicKey)
	if e != nil {
		return
	}
	w, e := NewEncoder(&buf, WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	if len(m.Metadata) != 0 {
		e = w.Encode(1, m.Metadata)
		if e != nil {
			return
		}
	}
	if len(m.Signature) != 0 {
		e = w.Encode(2, m.Signature)
		if e != nil {
			return
		}
	}
	b = buf.Bytes()
	return
}
