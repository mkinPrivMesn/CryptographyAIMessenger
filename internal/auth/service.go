package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/MkinPrivMesn/CryptographyAIMessenger/pkg/crypto"
	"github.com/google/uuid"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// проверка занятости ника
func (s *Service) FindTheNameInDataBase(username string) (bool, error) {
	// making encrypted username
	hexKey := os.Getenv("SERVER_SECRET")
	hexIV := os.Getenv("USERNAME_IV")

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return true, err
	}

	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return true, err
	}

	usernameEncrypted, err := crypto.EncryptUsername(username, key, iv)
	if err != nil {
		return true, err
	}

	// check username is taken
	nickNameIsExists, err := s.repo.FindUsername(usernameEncrypted)
	if err != nil {
		return true, err
	}

	if nickNameIsExists {
		return true, nil
	}

	return false, nil
}

// этот метод вызывает модуль репозитория и передает ему юзера
func (s *Service) Register(req RegisterRequest) (string, string, error) {

	// getting KEY and IV for crypto packet from .env
	hexKey := os.Getenv("SERVER_SECRET")
	hexIV := os.Getenv("USERNAME_IV")

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", "", err
	}

	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return "", "", err
	}

	// encryption of username
	usernameEncrypted, err := crypto.EncryptUsername(req.Username, key, iv)
	if err != nil {
		return "", "", err
	}

	// check if username already exists
	exists, err := s.repo.FindUsername(usernameEncrypted)
	if err != nil {
		return "", "", err
	}
	if exists {
		return "", "", errors.New("username already taken")
	}

	// creating user object
	id := uuid.New().String()

	user := User{
		RandomUUID:        id,
		UsernameEncrypted: usernameEncrypted,
		PublicKey:         req.PublicKey,
		EncryptedBlob:     req.EncryptedBlob,
		Salt1:             req.Salt1,
		AuthHash:          req.AuthHash,
		Salt2:             req.Salt2,
		TokenVersion:      1,
	}

	// save user to DB first
	err = s.repo.CreateUser(user)
	if err != nil {
		return "", "", err
	}

	// generating tokens
	jwtSecret := os.Getenv("JWT_SECRET")

	accessToken, err := crypto.GenerateAccessToken(id, user.TokenVersion, jwtSecret)
	if err != nil {
		return "", "", err
	}

	refreshToken, refreshTokenHash, err := crypto.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	// save refresh token
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	err = s.repo.SaveRefreshToken(user.RandomUUID, refreshTokenHash, expiresAt)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *Service) LoginSalt(username string) (string, error) {
	salt2, err := s.repo.GetSalt2FromDB(username)
	if err != nil {
		return "", err
	}

	return salt2, nil
}
