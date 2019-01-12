package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func AesDecrypt(secretData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	originData := make([]byte, len(secretData))
	blockMode.CryptBlocks(originData, secretData)
	originData = pkcs7unpadding(originData)
	return originData, nil
}

func AesEncrypt(originData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	originData = pkcs7padding(originData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	secretData := make([]byte, len(originData))
	blockMode.CryptBlocks(secretData, originData)
	return secretData, nil
}

func pkcs7padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

func pkcs7unpadding(data []byte) []byte {
	length := len(data)
	padLen := int(data[length-1])
	return data[:(length - padLen)]
}
