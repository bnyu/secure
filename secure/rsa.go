package secure

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Sign(private *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, h[:])
}

func Verify(public *rsa.PublicKey, data, signature []byte) error {
	h := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(public, crypto.SHA256, h[:], signature)
}

func Decrypt(private *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, private, cipher)
}

func Encrypt(public *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, public, data)
}
