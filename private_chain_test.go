package seal_test

import (
	"crypto"
	"testing"

	"github.com/zuiwuchang/seal"
)

func TestPrivateChain(t *testing.T) {
	pri, e := seal.New(seal.Metadata{
		Hash:           crypto.SHA256,
		Organization:   `cerberus`,
		Organizational: `A`,
		Content:        []byte(`root ca`),
	}, 1024)
	if e != nil {
		t.Fatal(`New`, e)
	}
	pri, e = pri.SignPrivate(seal.Metadata{
		Hash:           crypto.SHA224,
		Organization:   `cerberus`,
		Organizational: `B`,
		Content:        []byte(`ca 0`),
	}, 1024)
	if e != nil {
		t.Fatal(`New`, e)
	}
	pri, e = pri.SignPrivate(seal.Metadata{
		Hash:           crypto.SHA1,
		Organization:   `cerberus`,
		Organizational: `C`,
		Content:        []byte(`ca B-0`),
	}, 1024)
	if e != nil {
		t.Fatal(`New`, e)
	}

	pri.Println()
}
