package beacon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/argon2"
	"strings"
)

func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func PasswordHash(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(h)
}
func PasswordOK(password, stored string) bool {
	p := strings.Split(stored, ".")
	if len(p) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(p[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(p[1])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

type Crypto struct {
	aead cipher.AEAD
	key  []byte
}

func NewCrypto(key []byte) (*Crypto, error) {
	if len(key) != 32 {
		return nil, errors.New("BEACON_KEY must be 32 bytes encoded as 64 hex characters")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	return &Crypto{a, key}, e
}
func (c *Crypto) Seal(data []byte, object string) []byte {
	nonce := make([]byte, c.aead.NonceSize())
	rand.Read(nonce)
	return c.aead.Seal(nonce, nonce, data, []byte(object))
}
func (c *Crypto) Open(data []byte, object string) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(data) < n {
		return nil, errors.New("invalid ciphertext")
	}
	return c.aead.Open(nil, data[:n], data[n:], []byte(object))
}
func (c *Crypto) Sign(s string) string {
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte("csrf:" + s))
	return hex.EncodeToString(h.Sum(nil))
}
func (c *Crypto) ValidCSRF(s string) bool {
	p := strings.Split(s, ".")
	return len(p) == 2 && len(p[0]) == 64 && hmac.Equal([]byte(c.Sign(p[0])), []byte(p[1]))
}
