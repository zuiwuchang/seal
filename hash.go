package seal

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"strconv"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"

	_ "golang.org/x/crypto/sha3"
)

var hashKeys map[string]crypto.Hash
var Hash = []crypto.Hash{
	// crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	// crypto.MD5SHA1,
	// crypto.RIPEMD160,
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

func init() {
	hashKeys = make(map[string]crypto.Hash, len(Hash))
	for _, h := range Hash {
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
