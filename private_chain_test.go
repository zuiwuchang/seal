package seal_test

import (
	"crypto"
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

}
