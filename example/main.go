package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"secure/trans"
)

type Arg struct {
	SecretData string `json:"secret_data"`
	SecretKey  string `json:"secret_key"`
	Signature  string `json:"signature"`
}

type Key struct {
	myKey    *rsa.PrivateKey
	otherKey *rsa.PublicKey
}

func (key Key) send(msg string) string {
	if d, k, s, err := trans.Send([]byte(msg), key.myKey, key.otherKey); err == nil {
		arg := Arg{
			SecretData: base64.StdEncoding.EncodeToString(d),
			SecretKey:  base64.StdEncoding.EncodeToString(k),
			Signature:  base64.StdEncoding.EncodeToString(s),
		}
		a, _ := json.Marshal(&arg)
		return string(a)
	}
	return ""
}

func (key Key) receive(msg string) string {
	var err error
	var arg Arg
	if err = json.Unmarshal([]byte(msg), &arg); err == nil {
		s, _ := base64.StdEncoding.DecodeString(arg.Signature)
		d, _ := base64.StdEncoding.DecodeString(arg.SecretData)
		k, _ := base64.StdEncoding.DecodeString(arg.SecretKey)
		if data, ok := trans.Receive(s, d, k, key.myKey, key.otherKey); ok {
			return string(data)
		}
	}
	return ""
}

func main() {
	var msgChan = make(chan string)
	a, b := parseRsaKey()
	go func() {
		str := "Hello World!"
		println("send: " + str)
		str = a.send(str)
		msgChan <- str
	}()
	str := b.receive(<-msgChan)
	println("receive: " + str)
}

func parseRsaKey() (a, b Key) {
	var (
		err        error
		aPri, aPub []byte
		bPri, bPub []byte
		aPrivate   *rsa.PrivateKey
		aPublic    *rsa.PublicKey
		bPrivate   *rsa.PrivateKey
		bPublic    *rsa.PublicKey
	)
	if aPri, aPub, err = generateRsaKey(1024); err != nil {
		panic(err)
	}
	if bPri, bPub, err = generateRsaKey(1024); err != nil {
		panic(err)
	}
	aPrivate, _ = x509.ParsePKCS1PrivateKey(aPri)
	bPrivate, _ = x509.ParsePKCS1PrivateKey(bPri)
	aPublic, _ = x509.ParsePKCS1PublicKey(aPub)
	bPublic, _ = x509.ParsePKCS1PublicKey(bPub)
	return Key{myKey: aPrivate, otherKey: bPublic}, Key{myKey: bPrivate, otherKey: aPublic}
}

func generateRsaKey(bits int) (private, public []byte, err error) {
	if pri, err := rsa.GenerateKey(rand.Reader, bits); err == nil {
		private = x509.MarshalPKCS1PrivateKey(pri)
		public = x509.MarshalPKCS1PublicKey(&pri.PublicKey)
	}
	return
}
