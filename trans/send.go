package trans

import (
	"crypto/rsa"
	"errors"
	"math/rand"
	"secure/secure"
)

func Send(originData []byte, senderKey *rsa.PrivateKey, receiverKey *rsa.PublicKey) (secretData, secretKey, signature []byte, err error) {
	if len(originData) == 0 {
		err = errors.New("origin data can not be empty")
		return
	}
	if secretData, secretKey, err = encrypt(receiverKey, originData); err != nil {
		return
	}
	signature, err = secure.Sign(senderKey, secretData)
	return
}

func encrypt(public *rsa.PublicKey, data []byte) (secretData, secretKey []byte, err error) {
	key := generateKey()
	if secretData, err = secure.AesEncrypt(data, key); err != nil {
		return
	}
	secretKey, err = secure.Encrypt(public, key)
	return
}

func generateKey() []byte {
	n := 32
	x := make([]byte, n)
	for i := 0; i < n; i++ {
		x[i] = byte(rand.Intn(256))
	}
	return x
}
