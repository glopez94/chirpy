-- name: GetUserFromRefreshToken :one
SELECT users.id, users.created_at, users.updated_at, users.email, users.hashed_password
FROM refresh_tokens
JOIN users ON refresh_tokens.user_id = users.id
WHERE refresh_tokens.token = $1 AND refresh_tokens.expires_at > NOW() AND refresh_tokens.revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = $2, updated_at = $3
WHERE token = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, NULL);