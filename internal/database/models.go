// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0

package database

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type Chirp struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Body      string
	UserID    uuid.NullUUID
}

type RefreshToken struct {
	Token     string
	CreatedAt time.Time
	UpdatedAt time.Time
	UserID    uuid.NullUUID
	ExpiresAt time.Time
	RevokedAt sql.NullTime
}

type User struct {
	ID             uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Email          string
	HashedPassword string
}
