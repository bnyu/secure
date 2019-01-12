package trans

import (
	"crypto/rsa"
	"secure/secure"
)

func Receive(signature, secretData, secretKey []byte, receiverKey *rsa.PrivateKey, senderKey *rsa.PublicKey) (data []byte, ok bool) {
	var err error
	if err = secure.Verify(senderKey, secretData, signature); err != nil {
		return nil, false
	}
	if data, err = decrypt(receiverKey, secretKey, secretData); err != nil {
		return nil, false
	}
	return data, true
}

func decrypt(private *rsa.PrivateKey, secretKey, secretData []byte) ([]byte, error) {
	key, err := secure.Decrypt(private, secretKey)
	if err != nil {
		return nil, err
	}
	return secure.AesDecrypt(secretData, key)
}
