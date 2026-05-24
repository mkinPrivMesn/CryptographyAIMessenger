package auth

import (
	"crypto/ed25519"
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

func (s *Service) RecoveryGetChallenge(req RecoveryRequest) (string, error) {
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

func (s *Service) RecoveryGetIdAndPubKey(username string, signature string) (string, string, error) {
	username_encrypted, err := s.encryptUsername(username)
	if err != nil {
		return "", "", err
	}

	exists, err := s.repo.FindUsername(username_encrypted)
	if err != nil {
		return "", "", err
	}

	if exists {
		user_id, pubKey, err := s.repo.GetUserIdPubKeyInDB(username_encrypted)
		if err != nil {
			return "", "", err
		}

		return user_id, pubKey, nil
	} else {
		fakePublic := os.Getenv("FAKE_PUBLIC")
		fakePublicBytes, err := hex.DecodeString(fakePublic)
		if err != nil {
			return "", "", err
		}

		fakeChallenge := make([]byte, 32)
		rand.Read(fakeChallenge)

		signatureBytes, err := hex.DecodeString(signature)
		if err != nil {
			return "", "", err
		}

		ed25519.Verify(fakePublicBytes, fakeChallenge, signatureBytes)

		s.repo.FindUsername(username_encrypted) // специальный холостой запрос для ттотго, чтобы потянуть время для timinng attack
		return "", "", ErrFakeUser
	}
}

func (s *Service) IsChallengeLegit(userId string, pubKey string, req RecoveryRequest) (bool, error) {
	challenges, err := s.repo.FindChallengeInDB(userId) // вот тут говнецо прячется
	if err != nil {
		return false, err
	}

	for _, c := range challenges {
		if c.ExpiresAt.Before(time.Now()) {
			s.repo.DeleteChallenge(c.Challenge)
			continue
		}

		pubKeyBytes, err := hex.DecodeString(pubKey)
		if err != nil {
			return false, err
		}
		signatureBytes, err := hex.DecodeString(req.Signature)
		if err != nil {
			return false, err
		}
		challengeBytes, err := hex.DecodeString(c.Challenge)
		if err != nil {
			return false, err
		}

		valid := ed25519.Verify(pubKeyBytes, challengeBytes, signatureBytes)
		s.repo.DeleteChallenge(c.Challenge) // удаляем в любом случае
		if valid {
			return true, nil
		}
	}

	return false, nil

}

func (s *Service) UpdateColumsForRecovery(user_id, salt1, salt2, encryptedBlob, authHash string) error {
	return s.repo.UpdateColumsForRecoveryInDB(user_id, salt1, salt2, encryptedBlob, authHash)
}

func (s *Service) DeleteAllRefreshTokens(user_id string) error {
	return s.repo.DeleteAllRefreshTokensInDB(user_id)
}

func (s *Service) IncrementTokenVersionAndReturnIt(user_id string) (int, error) {
	tokenVersion, err := s.repo.InnncrementTokenVersion(user_id)
	if err != nil {
		return 0, err
	}

	return tokenVersion, nil
}
