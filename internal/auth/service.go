package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

func (s *Service) encryptUsername(username string) (string, error) {
	hexKey := os.Getenv("SERVER_SECRET")
	hexIV := os.Getenv("USERNAME_IV")

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return "", err
	}

	return crypto.EncryptUsername(username, key, iv)
}

// проверка занятости ника
func (s *Service) FindTheNameInDataBase(username string) (bool, error) {
	usernameEncrypted, err := s.encryptUsername(username)
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

	usernameEncrypted, err := s.encryptUsername(req.Username)
	if err != nil {
		return "", "", err
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

	// then generating tokens
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

func (s *Service) GetSalt2ByLogin(username string) (string, error) {
	usernameEncrypteed, err := s.encryptUsername(username)
	if err != nil {
		return "", err
	}

	return s.repo.GetSalt2FromDB(usernameEncrypteed)
}

func (s *Service) FindAuthHashInDB(username string) (string, error) {
	usernameEncrypteed, err := s.encryptUsername(username)
	if err != nil {
		return "", err
	}

	AuthHashFromDataBase, err := s.repo.GetAuthHashFromDB(usernameEncrypteed)
	if err != nil {
		return "", err
	}

	return AuthHashFromDataBase, nil
}

func (s *Service) FindBlobAndSalt1InDB(username string) (string, string, error) {
	usernameEncrypteed, err := s.encryptUsername(username)
	if err != nil {
		return "", "", err
	}

	Blob, Salt1, err := s.repo.GetBlobAndSalt1FromDB(usernameEncrypteed)
	if err != nil {
		return "", "", err
	}

	return Blob, Salt1, nil
}

func (s *Service) GetUserIDAndTokenVersionInDB(username string) (string, int, error) {
	usernameEncrypteed, err := s.encryptUsername(username)
	if err != nil {
		return "", 0, err
	}

	UserID, TokenVersion, err := s.repo.GetUserIDAndTokenVersionFromDB(usernameEncrypteed)
	if err != nil {
		return "", 0, err
	}

	return UserID, TokenVersion, nil
}

func (s *Service) SaveRefreshTokenForLogin(userID string, tokenHash string, expiresAt time.Time) error {
	return s.repo.SaveRefreshToken(userID, tokenHash, expiresAt)
}

//		########################################
//		#####        LogOut Methods        #####
//		########################################

func (s *Service) Logout(refreshToken string) error {
	// захешировать шмак 256
	hash := sha256.Sum256([]byte(refreshToken))
	hashOfRefreshToken := hex.EncodeToString(hash[:])

	err := s.repo.DeleteRefreshToken(hashOfRefreshToken)
	if err != nil {
		return err
	}

	return nil
}

//		########################################
//		#####      ChangePass Methods      #####
//		########################################

func (s *Service) RecoveryGetChallenge(req LoginRequest) (string, error) {
	username_encrypted, err := s.encryptUsername(req.Username)
	if err != nil {
		return "", err
	}

	exists, err := s.repo.FindUsername(username_encrypted)
	if err != nil {
		return "", err
	}

	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		return "", err
	}
	challengeHex := hex.EncodeToString(challenge)

	if exists {
		user_id, err := s.repo.GetIDByUsername(username_encrypted)
		if err != nil {
			return "", err
		}

		err1 := s.repo.AddChallengeToDB(challengeHex, user_id, time.Now().Add(5*time.Minute))
		if err1 != nil {
			return "", err1
		}

	} else {
		s.repo.GetIDByUsername(username_encrypted) // намеренно игнорируем ошибку
	}

	return challengeHex, nil
}
