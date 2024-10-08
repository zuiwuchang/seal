package seal_test

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	"github.com/zuiwuchang/seal"
)

func TestMarshalRootChain(t *testing.T) {
	pri, e := seal.New(seal.Metadata{
		Hash:           crypto.SHA256,
		Organization:   `cerberus`,
		Organizational: `A`,
		Content:        []byte(`root ca`),
	}, 1024)
	if e != nil {
		t.Fatal(`New`, e)
	}
	pri0, e := seal.ParsePrivateChain(pri.Marshal())
	if e != nil {
		t.Fatal(`ParsePrivateChain`, e)
	}
	if !pri.PrivateKey().Equal(pri0.PrivateKey()) {
		t.Fatal(`PrivateKey not equal`)
	}

	pub := pri0.PublicChain
	pub0, e := seal.ParsePublicChain(pub.Marshal())
	if e != nil {
		t.Fatal(`ParsePublicChain`, e)
	}
	if !pub0.PublicKey().Equal(pub.PublicKey()) {
		t.Fatal(`PublicKey not equal`)
	}

	// content
	content := []byte(`cerberus is an idea`)
	c, e := pri.SignContent(seal.Metadata{
		Hash:    crypto.SHA256,
		Content: content,
	})
	if e != nil {
		t.Fatal(`SignContent`, e)
	}
	pub0, e = seal.ParsePublicChain(c.Marshal())
	if e != nil {
		t.Fatal(`ParsePublicChain`, e)
	}
	if !pub0.PublicKey().Equal(pub.PublicKey()) {
		t.Fatal(`PublicKey not equal`)
	}
	if !bytes.Equal(content, pub0.Metadata().Content) {
		t.Fatal(`Content not equal`)
	}
}

func TestMarshalChain(t *testing.T) {
	pri, e := seal.New(seal.Metadata{
		Hash:           crypto.SHA256,
		Organization:   `cerberus`,
		Organizational: `A`,
		Content:        []byte(`root ca`),
	}, 1024)
	if e != nil {
		t.Fatal(`New`, e)
	}
	for i := 0; i < 6; i++ {
		pri, e = pri.SignPrivate(seal.Metadata{
			Hash:           crypto.SHA224,
			Organization:   `cerberus`,
			Organizational: fmt.Sprintf(`C %d`, i),
			Content:        []byte(fmt.Sprintf(`ca %d`, i)),
		}, 1024)
		if e != nil {
			t.Fatal(`New`, e)
		}
	}

	pri0, e := seal.ParsePrivateChain(pri.Marshal())
	if e != nil {
		t.Fatal(`ParsePrivateChain`, e)
	}
	if !pri.PrivateKey().Equal(pri0.PrivateKey()) {
		t.Fatal(`PrivateKey not equal`)
	}

	pub := pri0.PublicChain
	pub0, e := seal.ParsePublicChain(pub.Marshal())
	if e != nil {
		t.Fatal(`ParsePublicChain`, e)
	}
	if !pub0.PublicKey().Equal(pub.PublicKey()) {
		t.Fatal(`PublicKey not equal`)
	}

	// content
	content := []byte(`cerberus is an idea`)
	c, e := pri.SignContent(seal.Metadata{
		Hash:    crypto.SHA256,
		Content: content,
	})
	if e != nil {
		t.Fatal(`SignContent`, e)
	}
	pub0, e = seal.ParsePublicChain(c.Marshal())
	if e != nil {
		t.Fatal(`ParsePublicChain`, e)
	}
	if !pub0.PublicKey().Equal(pub.PublicKey()) {
		t.Fatal(`PublicKey not equal`)
	}
	if !bytes.Equal(content, pub0.Metadata().Content) {
		t.Fatal(`Content not equal`)
	}

}
