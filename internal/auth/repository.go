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
