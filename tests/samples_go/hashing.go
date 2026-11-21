// Sample: hashes, MACs, KDFs and ciphers in Go. Never compiled or run; the scanner only reads it.
// An "expect" comment at the end of a line lists the algorithm ids that must be found there.
package samples

import (
	"crypto/aes"    // expect: AES
	"crypto/cipher"
	"crypto/des"    // expect: DES
	"crypto/hmac"   // expect: HMAC
	"crypto/md5"    // expect: MD5
	"crypto/pbkdf2" // expect: PBKDF2
	"crypto/sha1"   // expect: SHA1
	"crypto/sha256" // expect: SHA256
	"crypto/sha512" // expect: SHA512

	"golang.org/x/crypto/bcrypt"           // expect: BCRYPT
	"golang.org/x/crypto/chacha20poly1305" // expect: CHACHA20_POLY1305
	xpbkdf2 "golang.org/x/crypto/pbkdf2"   // expect: PBKDF2
)

const legacyIterations = 4096

func checksum(data []byte) [16]byte {
	return md5.Sum(data) // expect: MD5
}

func fingerprint(data []byte) [20]byte {
	return sha1.Sum(data) // expect: SHA1
}

func good(data []byte) [32]byte {
	return sha256.Sum256(data) // expect: SHA256
}

func short(data []byte) [28]byte {
	return sha256.Sum224(data) // expect: SHA224
}

func big(data []byte) [48]byte {
	return sha512.Sum384(data) // expect: SHA384
}

func tag(key, data []byte) []byte {
	m := hmac.New(sha1.New, key) // expect: HMAC_SHA1
	m.Write(data)
	return m.Sum(nil)
}

func strongTag(key []byte) []byte {
	return hmac.New(sha512.New, key).Sum(nil) // expect: HMAC
}

func weakKdf(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, legacyIterations, 32) // expect: PBKDF2
}

func strongKdf(password, salt []byte) []byte {
	return xpbkdf2.Key(password, salt, 600_000, 32, sha512.New) // expect: PBKDF2_STRONG
}

func hashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost) // expect: BCRYPT
}

func cbc(key, iv []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key) // expect: AES
	if err != nil {
		return nil, err
	}
	return cipher.NewCBCEncrypter(block, iv), nil // expect: CBC
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, _ := aes.NewCipher(key) // expect: AES
	return cipher.NewGCM(block)    // expect: AES_GCM
}

func tripleDes(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key) // expect: TDES
}

func chacha(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key) // expect: CHACHA20_POLY1305
}

func notCode() string {
	// md5.Sum in a comment is not a finding
	return `sha1.Sum in a raw string is not one either`
}
