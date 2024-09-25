package seal

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/zuiwuchang/seal/raw"
	"google.golang.org/protobuf/proto"
)

// 公鑰鏈，用於回溯簽發源
type PublicChain struct {
	raw []byte
	md  *Metadata
}

func (p *PublicChain) Println() {
	b := p.raw
	for i := 0; len(b) != 0; i++ {
		fmt.Println(i, `------------------PublicChain------------------`)
		var m raw.PublicChain
		e := proto.Unmarshal(b, &m)
		if e != nil {
			log.Println(e)
			break
		}
		b = m.Parent
		var md raw.Metadata
		e = proto.Unmarshal(m.PublicKey.Metadata, &md)
		if e != nil {
			log.Println(e)
			break
		}

		fmt.Println(`hash:`, md.Hash)
		if len(md.Parent) != 0 {
			fmt.Println(`parent:`, base64.RawURLEncoding.EncodeToString(md.Parent))
		}
		if len(md.PublicKey) != 0 {
			fmt.Println(`publicKey:`, base64.RawURLEncoding.EncodeToString(md.PublicKey))
		}
		if md.Afrer > 0 {
			fmt.Println(`after:`, time.Unix(md.Afrer, 0).Local())
		}
		if md.Before > 0 {
			fmt.Println(`before:`, time.Unix(md.Before, 0).Local())
		}
		if md.Country != `` {
			fmt.Println(`country:`, md.Country)
		}
		if md.State != `` {
			fmt.Println(`state:`, md.State)
		}
		if md.Locality != `` {
			fmt.Println(`locality:`, md.Locality)
		}
		if md.Organization != `` {
			fmt.Println(`organization:`, md.Organization)
		}
		if md.Organizational != `` {
			fmt.Println(`organizational:`, md.Organizational)
		}
		if len(md.Content) != 0 {
			fmt.Printf("content: %s\n", md.Content)
		}

	}
}
func newPublicChain(parent []byte, pri *rsa.PrivateKey, md *Metadata) (*PublicChain, error) {
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
	raw, e := proto.Marshal(&raw.PublicChain{
		Parent: parent,
		PublicKey: &raw.PublicKey{
			Metadata:  b,
			Signature: sig,
		},
	})
	if e != nil {
		return nil, e
	}
	return &PublicChain{
		raw: raw,
		md:  md,
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
	for md.Parent != nil {
		chain, md, e = parsePublicChain(chain.Parent, now)
		if e != nil {
			return nil, e
		}
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
	e = rsa.VerifyPKCS1v15(parent, hash, hashed, m.PublicKey.Signature)
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

// 驗證鏈當前是否有效
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
