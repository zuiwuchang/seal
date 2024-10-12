package frame

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/zuiwuchang/seal/raw"
)

var ErrNotPrivateChain = errors.New(`not a private chain`)

func UnmarshalMetadata(b []byte, m *raw.Metadata) (e error) {
	fmt.Println(b)
	os.Exit(1)
	// dec,e:=	NewDecoder(bytes.NewReader(b), WithId(8), WithPayload(32))
	// if e!=nil{
	// 	return
	// }
	// var buf bytes.Buffer
	// e = buf.WriteByte(Metadata)
	// if e != nil {
	// 	return
	// }

	// w, e := NewEncoder(&buf, WithId(8), WithPayload(32))
	// if e != nil {
	// 	return
	// }

	// if len(m.Hash) != 0 {
	// 	_, e = w.EncodeString(1, m.Hash)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.Parent) != 0 {
	// 	_, e = w.Encode(2, m.Parent)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.PublicKey) != 0 {
	// 	_, e = w.Encode(3, m.PublicKey)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if m.Afrer > 0 {
	// 	t := make([]byte, 8)
	// 	binary.BigEndian.PutUint64(b, uint64(m.Afrer))
	// 	_, e = w.Encode(4, t)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if m.Before > 0 {
	// 	t := make([]byte, 8)
	// 	binary.BigEndian.PutUint64(b, uint64(m.Before))
	// 	_, e = w.Encode(5, t)
	// 	if e != nil {
	// 		return
	// 	}
	// }

	// if len(m.Country) != 0 {
	// 	_, e = w.EncodeString(6, m.Country)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.State) != 0 {
	// 	_, e = w.EncodeString(7, m.State)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.Locality) != 0 {
	// 	_, e = w.EncodeString(8, m.Locality)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.Organization) != 0 {
	// 	_, e = w.EncodeString(9, m.Organization)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.Organizational) != 0 {
	// 	_, e = w.EncodeString(9, m.Organizational)
	// 	if e != nil {
	// 		return
	// 	}
	// }
	// if len(m.Content) != 0 {
	// 	_, e = w.Encode(11, m.Content)
	// 	if e != nil {
	// 		return
	// 	}
	// }

	// b = buf.Bytes()
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
		id uint64
	)
	for {
		id, _, e = dec.Decode()
		fmt.Println(id, e)
		if e != nil {
			break
		}
	}
	return
}
