package seal

import (
	"crypto"
	"strconv"
)

var hashKeys map[string]crypto.Hash

func init() {
	items := []crypto.Hash{
		crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.MD5SHA1,
		crypto.RIPEMD160,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_256,
		crypto.BLAKE2b_384,
		crypto.BLAKE2b_512,
	}
	hashKeys = make(map[string]crypto.Hash, len(items))
	for _, h := range items {
		hashKeys[h.String()] = h
	}
}
func GetHash(name string) crypto.Hash {
	return hashKeys[name]
}

type HashError string

func (s HashError) Error() string {
	return ` hash ` + strconv.Quote(string(s)) + ` not available`
}
