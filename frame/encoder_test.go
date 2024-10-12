package frame_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/zuiwuchang/seal/frame"
)

func TestEncoder(t *testing.T) {

	var buf bytes.Buffer
	enc, e := frame.NewEncoder(&buf, frame.WithId(8), frame.WithPayload(32))
	if e != nil {
		t.Fatal(e)
	}
	for i := 7; i <= 12; i++ {
		e = enc.EncodeString(uint64(i), fmt.Sprintf(`message %v`, i))
		if e != nil {
			t.Fatal(e)
		}
	}
	dec, e := frame.NewDecoder(&buf, frame.WithId(8), frame.WithPayload(32))
	if e != nil {
		t.Fatal(e)
	}

	for {
		id, data, e := dec.Decode()
		if e != nil {
			if e == io.EOF {
				break
			}
			t.Fatal(e)
		}
		fmt.Println(id, string(data))
	}
}
