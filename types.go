package seal

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/zuiwuchang/seal/raw"
)

// 簽名元信息
type Metadata struct {
	// 簽名使用的 hash 算法名稱
	Hash crypto.Hash
	// 使用此公鑰 驗證簽名，如果沒有表示它是自簽名的
	Parent *rsa.PublicKey

	// 公鑰，驗證它簽名的數據是否有效
	PublicKey *rsa.PublicKey

	// unix 表示此簽名有效起始時間，<1 則表示沒有此限制
	Afrer time.Time
	// unix 表示此簽名有效截止時間，<1 則表示沒有此限制
	Before time.Time

	// 可選的 國家名稱
	Country string
	// 可選的 /州 名稱
	State string
	// 可選的 地點或城市名稱
	Locality string
	// 可選的 組織或公司名稱
	Organization string
	// 可選的 組織單位或公司部門
	Organizational string
	// 可選的 被簽名的附帶內容
	Content []byte
}

func (md *Metadata) toRaw() *raw.Metadata {
	m := &raw.Metadata{
		Hash: md.Hash.String(),
		// Parent []byte `protobuf:"bytes,2,opt,name=parent,proto3" json:"parent,omitempty"`
		// 公鑰，驗證它簽名的數據是否有效
		// PublicKey: x509.MarshalPKCS1PublicKey(md.PublicKey),
		// // unix 表示此簽名有效起始時間，<1 則表示沒有此限制
		// Afrer int64 `protobuf:"varint,4,opt,name=afrer,proto3" json:"afrer,omitempty"`
		// // unix 表示此簽名有效截止時間，<1 則表示沒有此限制
		// Before int64 `protobuf:"varint,5,opt,name=before,proto3" json:"before,omitempty"`
		// 可選的 國家名稱
		Country: md.Country,
		// 可選的 /州 名稱
		State: md.State,
		// 可選的 地點或城市名稱
		Locality: md.Locality,
		// 可選的 組織或公司名稱
		Organization: md.Organization,
		// 可選的 組織單位或公司部門
		Organizational: md.Organizational,
		// 可選的 被簽名的附帶內容
		Content: md.Content,
	}
	if md.Parent != nil {
		m.Parent = x509.MarshalPKCS1PublicKey(md.Parent)
	}
	if md.PublicKey != nil {
		m.PublicKey = x509.MarshalPKCS1PublicKey(md.PublicKey)
	}
	if !md.Afrer.IsZero() {
		m.Afrer = md.Afrer.Unix()
	}
	if !md.Before.IsZero() {
		m.Before = md.Before.Unix()
	}
	return m
}
