package seal

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/zuiwuchang/seal/raw"
	"google.golang.org/protobuf/proto"
)

// 公鑰鏈，用於回溯簽發源
type PublicChain struct {
	raw []byte
	md  *Metadata

	parent *PublicChain
}

func newPublicChain(parent *PublicChain, pri *rsa.PrivateKey, md *Metadata) (*PublicChain, error) {
	b, e := proto.Marshal(md.toRaw())
	if e != nil {
		return nil, e
	}
	h := md.Hash.New()
	h.Write(b)
	hashed := h.Sum(nil)
	sig, e := rsa.SignPKCS1v15(nil, pri, md.Hash, hashed)
	if e != nil {
		return nil, e
	}
	var parentRaw []byte
	if parent != nil {
		parentRaw = parent.raw
	}
	raw, e := proto.Marshal(&raw.PublicChain{
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
		raw:    raw,
		md:     md,
		parent: parent,
	}, nil
}

// 將公鏈序列化，以便於網路傳輸或存儲
func (p *PublicChain) Marshal() []byte {
	return p.raw
}

// 加載序列化的公鏈到內存
func ParsePublicChain(b []byte) (*PublicChain, error) {
	return ParsePublicChainWithTime(b, time.Now().Unix())
}

// 加載序列化的公鏈到內存
// now 如果爲 < 1 則不驗證時間
func ParsePublicChainWithTime(b []byte, now int64) (*PublicChain, error) {
	// 加載 PublicChain
	chain, md, e := parsePublicChain(b, now)
	if e != nil {
		return nil, e
	}
	pub := &PublicChain{
		raw: b,
		md:  md,
	}

	// 驗證簽名鏈
	var (
		last    = pub
		current *PublicChain
	)
	for md.Parent != nil {
		b = chain.Parent
		chain, md, e = parsePublicChain(b, now)
		if e != nil {
			return nil, e
		}
		current = &PublicChain{
			raw: b,
			md:  md,
		}
		last.parent = current
		last = current
	}
	return pub, nil
}
func parsePublicChain(b []byte, at int64) (
	publicChain *raw.PublicChain,
	metadata *Metadata,
	e error) {
	var m raw.PublicChain
	e = proto.Unmarshal(b, &m)
	if e != nil {
		return
	}
	var md raw.Metadata
	e = proto.Unmarshal(m.PublicKey.Metadata, &md)
	if e != nil {
		return
	}
	hash := GetHash(md.Hash)
	if !hash.Available() {
		e = HashError(md.Hash)
		return
	}
	var pub, parent *rsa.PublicKey
	if len(md.Parent) == 0 {
		parent, e = x509.ParsePKCS1PublicKey(md.PublicKey)
		if e != nil {
			return
		}
		pub = parent
	} else {
		parent, e = x509.ParsePKCS1PublicKey(md.Parent)
		if e != nil {
			return
		}
		pub, e = x509.ParsePKCS1PublicKey(md.PublicKey)
		if e != nil {
			return
		}
	}
	h := hash.New()
	h.Write(m.PublicKey.Metadata)
	hashed := h.Sum(nil)
	e = rsa.VerifyPKCS1v15(pub, hash, hashed, m.PublicKey.Signature)
	if e != nil {
		return
	}
	publicChain = &m
	metadata = &Metadata{
		Hash:           hash,
		PublicKey:      pub,
		Country:        md.Country,
		State:          md.State,
		Locality:       md.Locality,
		Organization:   md.Organization,
		Organizational: md.Organizational,
		Content:        md.Content,
	}
	if len(md.Parent) != 0 {
		metadata.Parent = parent
	}
	if md.Afrer > 0 {
		if at > 0 && at < md.Afrer {
			e = ErrDateYet
			return
		}
		metadata.Afrer = time.Unix(md.Afrer, 0)
	}
	if md.Before > 0 {
		if at > 0 && at > md.Before {
			e = ErrExpired
			return
		}
		metadata.Before = time.Unix(md.Before, 0)
	}
	return
}

// 驗證鏈當前時間是否有效
func (p *PublicChain) Valid() error {
	if p == nil || p.md == nil {
		return ErrNil
	}
	if !p.md.Afrer.IsZero() {
		now := time.Now()
		if now.Before(p.md.Afrer) {
			return ErrDateYet
		} else if !p.md.Before.IsZero() {
			if now.After(p.md.Before) {
				return ErrExpired
			}
		}
	} else if !p.md.Before.IsZero() {
		now := time.Now()
		if now.After(p.md.Before) {
			return ErrExpired
		}
	}
	return nil
}

// 驗證 sig 是否是 hashed 的簽名
func (p *PublicChain) Verify(hash crypto.Hash, hashed []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(p.md.PublicKey, hash, hashed, sig)
}

// 返回它是由誰簽發的，如果爲 nil 則表示自簽發
func (p *PublicChain) Parent() *PublicChain {
	return p.parent
}

// 返回公鑰
func (p *PublicChain) PublicKey() *rsa.PublicKey {
	return p.md.PublicKey
}

// 返回元信息，請勿修改
func (p *PublicChain) Metadata() *Metadata {
	return p.md
}
