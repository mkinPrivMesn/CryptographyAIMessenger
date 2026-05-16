package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

func EncryptUsername(username string, key []byte, iv []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	if len(iv) != 12 {
		return "", errors.New("iv must be 12 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nil, iv, []byte(username), nil)
	return hex.EncodeToString(encrypted), nil
}

func DecryptUsername(encryptedHex string, key []byte, iv []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}
	if len(iv) != 12 {
		return "", errors.New("iv must be 12 bytes")
	}

	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decrypted, err := gcm.Open(nil, iv, encrypted, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
