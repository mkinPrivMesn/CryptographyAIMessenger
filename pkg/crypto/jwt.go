package crypto

import (
	"time"

	"github.com/golang-jwt/jwt/v5"

	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

type Claims struct {
	UserID       string `json:"user_id"`
	TokenVersion int    `json:"token_version"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID string, tokenVersion int, secret string) (string, error) {
	claims := Claims{
		UserID:       userID,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func GenerateRefreshToken() (string, string, error) {
	// генерируем случайные 64 байта
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", "", err
	}

	// сам токен — отправляем клиенту
	token := hex.EncodeToString(bytes)

	// хеш токена
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	return token, tokenHash, nil
}
