package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/zuiwuchang/seal/raw"
)

var ErrNotPrivateChain = errors.New(`not a private chain`)
var ErrNotMetadata = errors.New(`not a metadata`)
var ErrNotPublicChain = errors.New(`not a public chain`)
var ErrNotPublicKey = errors.New(`not a public key`)

func UnmarshalMetadata(b []byte, m *raw.Metadata) (e error) {
	if len(b) < 1 || b[0] != Metadata {
		e = ErrNotMetadata
		return
	}
	dec, e := NewDecoder(bytes.NewReader(b[1:]), WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	var (
		id   uint64
		data []byte
	)
	for {
		id, data, e = dec.Decode()
		if e != nil {
			break
		}
		switch id {
		case 1:
			m.Hash = BytesToString(data)
		case 2:
			m.Parent = data
		case 3:
			m.PublicKey = data
		case 4:
			if len(data) == 8 {
				m.Afrer = int64(binary.BigEndian.Uint64(data))
			}
		case 5:
			if len(data) == 8 {
				m.Before = int64(binary.BigEndian.Uint64(data))
			}
		case 6:
			m.Country = BytesToString(data)
		case 7:
			m.State = BytesToString(data)
		case 8:
			m.Locality = BytesToString(data)
		case 9:
			m.Organization = BytesToString(data)
		case 10:
			m.Organizational = BytesToString(data)
		case 11:
			m.Content = data
		}
	}
	if e == io.EOF {
		e = nil
	}
	return
}
func UnmarshalPublicKey(b []byte, m *raw.PublicKey) (e error) {
	if len(b) < 1 || b[0] != PublicKey {
		e = ErrNotPublicKey
		return
	}
	dec, e := NewDecoder(bytes.NewReader(b[1:]), WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	var (
		id   uint64
		data []byte
	)
	for {
		id, data, e = dec.Decode()
		if e != nil {
			break
		}
		switch id {
		case 1:
			m.Metadata = data
		case 2:
			m.Signature = data
		}
	}
	if e == io.EOF {
		e = nil
	}
	return
}
func UnmarshalPublicChain(b []byte, m *raw.PublicChain) (e error) {
	if len(b) < 1 || b[0] != PublicChain {
		e = ErrNotPublicChain
		return
	}
	dec, e := NewDecoder(bytes.NewReader(b[1:]), WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	var (
		id   uint64
		data []byte
	)
	for {
		id, data, e = dec.Decode()
		if e != nil {
			break
		}
		switch id {
		case 1:
			m.Parent = data
		case 2:
			if len(data) != 0 {
				var pk raw.PublicKey
				e = UnmarshalPublicKey(data, &pk)
				if e != nil {
					return
				}
				m.PublicKey = &pk
			}
		}
	}
	if e == io.EOF {
		e = nil
	}
	return
}
func UnmarshalPrivateChain(b []byte, m *raw.PrivateChain) (e error) {
	if len(b) < 1 || b[0] != PrivateChain {
		e = ErrNotPrivateChain
		return
	}
	dec, e := NewDecoder(bytes.NewReader(b[1:]), WithId(8), WithPayload(32))
	if e != nil {
		return
	}
	var (
		id   uint64
		data []byte
	)
	for {
		id, data, e = dec.Decode()
		if e != nil {
			break
		}
		switch id {
		case 1:
			m.PublicChain = data
		case 2:
			m.PrivateKey = data
		}
	}
	if e == io.EOF {
		e = nil
	}
	return
}
