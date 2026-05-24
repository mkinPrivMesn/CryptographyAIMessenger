package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(user User) error {
	_, err := r.db.Exec(
		context.Background(),
		`INSERT INTO users 
    (id, username_encrypted, public_key, encrypted_blob, salt1, auth_hash, salt2, token_version) 
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		user.RandomUUID,
		user.UsernameEncrypted,
		user.PublicKey,
		user.EncryptedBlob,
		user.Salt1,
		user.AuthHash,
		user.Salt2,
		user.TokenVersion,
	)

	return err
}

func (r *Repository) FindUsername(Username string) (bool, error) {
	var exists bool

	err := r.db.QueryRow(
		context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE username_encrypted = $1)",
		Username,
	).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *Repository) SaveRefreshToken(userID string, tokenHash string, expiresAt time.Time) error {
	id := uuid.New().String()
	_, err := r.db.Exec(
		context.Background(),
		`INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) 
        VALUES ($1, $2, $3, $4)`,
		id,
		userID,
		tokenHash,
		expiresAt,
	)

	return err
}

func (r *Repository) GetSalt2FromDB(username string) (string, error) {
	var salt2 string

	err := r.db.QueryRow(
		context.Background(),
		"SELECT salt2 FROM users WHERE username_encrypted = $1",
		username,
	).Scan(&salt2)

	if err != nil {
		return "", err
	}

	return salt2, nil
}

func (r *Repository) GetAuthHashFromDB(username string) (string, error) {
	var AuthHashFromDataBase string

	err := r.db.QueryRow(
		context.Background(),
		"SELECT auth_hash FROM users WHERE username_encrypted = $1",
		username,
	).Scan(&AuthHashFromDataBase)

	if err != nil {
		return "", err
	}

	return AuthHashFromDataBase, nil
}

func (r *Repository) GetBlobAndSalt1FromDB(username string) (string, string, error) {
	var Blob, Salt1 string

	err := r.db.QueryRow(
		context.Background(),
		"SELECT encrypted_blob, salt1 FROM users WHERE username_encrypted = $1",
		username,
	).Scan(&Blob, &Salt1)

	if err != nil {
		return "", "", err
	}

	return Blob, Salt1, nil
}

func (r *Repository) GetUserIDAndTokenVersionFromDB(username string) (string, int, error) {
	var UserID string
	var TokenVersion int

	err := r.db.QueryRow(
		context.Background(),
		"SELECT id, token_version FROM users WHERE username_encrypted = $1",
		username,
	).Scan(&UserID, &TokenVersion)

	if err != nil {
		return "", 0, err
	}

	return UserID, TokenVersion, nil
}

//		########################################
//		#####      TokenVersion check      #####
//		########################################

func (r *Repository) GetTokenVersionInDB(UserID string) (int, error) {
	var versionInDB int
	err := r.db.QueryRow(
		context.Background(),
		"SELECT token_version FROM users WHERE id = $1",
		UserID,
	).Scan(&versionInDB)
	if err != nil {
		return 0, err
	}

	return versionInDB, nil
}

func (r *Repository) DeleteRefreshToken(hashOfRefreshToken string) error {
	_, err := r.db.Exec(
		context.Background(),
		"DELETE FROM refresh_tokens WHERE token_hash = $1",
		hashOfRefreshToken,
	)
	return err
}

//		########################################
//		#####      ChangePass Methods      #####
//		########################################

func (r *Repository) GetIDByUsername(username string) (string, error) {
	var userId string

	err := r.db.QueryRow(
		context.Background(),
		"SELECT id FROM users WHERE username_encrypted = $1",
		username,
	).Scan(&userId)
	return userId, err
}

func (r *Repository) AddChallengeToDB(challengeHex, userId string, expiresAt time.Time) error {
	_, err := r.db.Exec(
		context.Background(),
		"INSERT INTO challenges (expires_at, user_id, challenge) VALUES ($1, $2, $3)",
		expiresAt, userId, challengeHex,
	)
	return err
}

func (r *Repository) GetUserIdPubKeyInDB(username_encrypted string) (string, string, error) {
	var userId, pubKey string

	err := r.db.QueryRow(
		context.Background(),
		"SELECT id, public_key FROM users WHERE username_encrypted = $1",
		username_encrypted,
	).Scan(&userId, &pubKey)
	return userId, pubKey, err
}

func (r *Repository) FindChallengeInDB(userId string) ([]ChallengeRow, error) {
	rows, err := r.db.Query(
		context.Background(),
		"SELECT challenge, expires_at FROM challenges WHERE user_id = $1",
		userId,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ChallengeRow // its slice that contains all challenges
	for rows.Next() {
		var row ChallengeRow
		if err := rows.Scan(&row.Challenge, &row.ExpiresAt); err != nil {
			return nil, err
		}
		result = append(result, row)
	}

	return result, nil
}

func (r *Repository) DeleteChallenge(challenge string) error {
	_, err := r.db.Exec(
		context.Background(),
		"DELETE FROM challenges WHERE challenge = $1",
		challenge,
	)
	return err
}

func (r *Repository) UpdateColumsForRecoveryInDB(user_id, salt1, salt2, encryptedBlob, authHash string) error {
	_, err := r.db.Exec(
		context.Background(),
		"UPDATE users SET salt1 = $1, salt2 = $2, encrypted_blob = $3, auth_hash = $4 WHERE id = $5",
		salt1, salt2, encryptedBlob, authHash, user_id,
	)
	return err
}

func (r *Repository) DeleteAllRefreshTokensInDB(user_id string) error {
	_, err := r.db.Exec(
		context.Background(),
		"DELETE FROM refresh_tokens WHERE user_id = $1",
		user_id,
	)
	return err
}

func (r *Repository) InnncrementTokenVersion(user_id string) (int, error) {
	var newVersion int

	err := r.db.QueryRow(
		context.Background(),
		"UPDATE users SET token_version = token_version + 1 WHERE id = $1 RETURNING token_version",
		user_id,
	).Scan(&newVersion)
	return newVersion, err
}
