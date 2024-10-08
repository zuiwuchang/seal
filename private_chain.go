package seal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/zuiwuchang/seal/raw"
	"google.golang.org/protobuf/proto"
)

// 私鑰鏈，用於簽名
type PrivateChain struct {
	*PublicChain
	raw        []byte
	privateKey *rsa.PrivateKey
}

// 將私鏈序列化，以便於網路傳輸或存儲
func (p *PrivateChain) Marshal() []byte {
	return p.raw
}

// 加載序列化的私鏈到內存
func ParsePrivateChain(b []byte) (*PrivateChain, error) {
	return ParsePrivateChainWithTime(b, time.Now().Unix())
}

// 加載序列化的私鏈到內存
// now 如果爲 < 1 則不驗證時間
func ParsePrivateChainWithTime(b []byte, now int64) (*PrivateChain, error) {
	var pri raw.PrivateChain
	e := proto.Unmarshal(b, &pri)
	if e != nil {
		return nil, e
	}
	privateKey, e := x509.ParsePKCS1PrivateKey(pri.PrivateKey)
	if e != nil {
		return nil, e
	}
	pub, e := ParsePublicChainWithTime(pri.PublicChain, now)
	if e != nil {
		return nil, e
	}
	if !pub.md.PublicKey.Equal(privateKey.Public()) {
		return nil, ErrDamaged
	}
	return &PrivateChain{
		PublicChain: pub,
		raw:         b,
		privateKey:  privateKey,
	}, nil
}

// 爲 hashed 簽名，並且返回簽名
func (p *PrivateChain) Sign(hash crypto.Hash, hashed []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, p.privateKey, hash, hashed)
}

// 創建一個私鏈
func New(md Metadata, bitSize int) (*PrivateChain, error) {
	if !md.Hash.Available() {
		return nil, HashError(md.Hash.String())
	}
	privateKey, e := rsa.GenerateKey(rand.Reader, bitSize)
	if e != nil {
		return nil, e
	}

	md.Parent = nil
	md.PublicKey = &privateKey.PublicKey
	pub, e := newPublicChain(nil, privateKey, &md)
	if e != nil {
		return nil, e
	}
	raw, e := proto.Marshal(&raw.PrivateChain{
		PublicChain: pub.raw,
		PrivateKey:  x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if e != nil {
		return nil, e
	}
	return &PrivateChain{
		PublicChain: pub,
		raw:         raw,
		privateKey:  privateKey,
	}, nil
}

// 返回私鑰
func (p *PrivateChain) PrivateKey() *rsa.PrivateKey {
	return p.privateKey
}

// 簽署一個私鏈
func (p *PrivateChain) SignPrivate(md Metadata, bitSize int) (*PrivateChain, error) {
	if !md.Hash.Available() {
		return nil, HashError(md.Hash.String())
	}
	privateKey, e := rsa.GenerateKey(rand.Reader, bitSize)
	if e != nil {
		return nil, e
	}
	md.Parent = &p.privateKey.PublicKey
	md.PublicKey = &privateKey.PublicKey
	pub, e := newPublicChain(p.PublicChain, privateKey, &md)
	if e != nil {
		return nil, e
	}
	raw, e := proto.Marshal(&raw.PrivateChain{
		PublicChain: pub.raw,
		PrivateKey:  x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if e != nil {
		return nil, e
	}
	return &PrivateChain{
		PublicChain: pub,
		raw:         raw,
		privateKey:  privateKey,
	}, nil
}

// 簽名一個內容
func (p *PrivateChain) SignContent(md Metadata) (*PublicChain, error) {
	if !md.Hash.Available() {
		return nil, HashError(md.Hash.String())
	}
	var parentRaw []byte
	if p.parent == nil {
		md.Parent = nil
	} else {
		md.Parent = p.parent.PublicKey()
		parentRaw = p.parent.raw
	}
	md.PublicKey = p.PublicKey()
	b, e := proto.Marshal(md.toRaw())
	if e != nil {
		return nil, e
	}
	h := md.Hash.New()
	h.Write(b)
	hashed := h.Sum(nil)
	sig, e := rsa.SignPKCS1v15(nil, p.privateKey, md.Hash, hashed)
	if e != nil {
		return nil, e
	}
	b, e = proto.Marshal(&raw.PublicChain{
		Parent: parentRaw,
		PublicKey: &raw.PublicKey{
			Metadata:  b,
			Signature: sig,
		},
	})
	if e != nil {
		return nil, e
	}
	return &PublicChain{
		raw:    b,
		parent: p.parent,
		md:     &md,
	}, nil
}
