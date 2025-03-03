package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// openssl rand -base64 64

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to make JWT: %v", err)
	}

	validatedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("Failed to validate JWT: %v", err)
	}

	if validatedUserID != userID {
		t.Fatalf("Expected user ID %v, got %v", userID, validatedUserID)
	}
}

func TestExpiredJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	expiresIn := -time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to make JWT: %v", err)
	}

	_, err = ValidateJWT(token, tokenSecret)
	if err == nil {
		t.Fatalf("Expected error for expired token, got nil")
	}
}

func TestInvalidSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "secret"
	wrongSecret := "wrongsecret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("Failed to make JWT: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatalf("Expected error for invalid secret, got nil")
	}
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer TOKEN_STRING")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if token != "TOKEN_STRING" {
		t.Fatalf("Expected token 'TOKEN_STRING', got %v", token)
	}
}

func TestGetBearerTokenMissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestGetBearerTokenInvalidFormat(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Invalid TOKEN_STRING")

	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}
