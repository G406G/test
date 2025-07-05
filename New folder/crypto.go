package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
)

var aesKey = []byte("ilovepornnet1234")

func xor(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key
	}
	return out
}

func pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

func unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) {
		return data
	}
	return data[:len(data)-padLen]
}

func Encrypt(msg string) (string, error) {
	plaintext := xor([]byte(msg), 0x37)
	padded := pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	encrypted := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(encrypted[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func Decrypt(enc string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	unpadded := unpad(decrypted)
	return string(xor(unpadded, 0x37)), nil
}
