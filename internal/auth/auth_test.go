package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}
	if hash == "secret123" {
		t.Fatal("HashPassword returned the plaintext password unchanged")
	}
}

func TestCheckPasswordHash_valid(t *testing.T) {
	hash, err := HashPassword("correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	match, err := CheckPasswordHash("correcthorsebatterystaple", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error: %v", err)
	}
	if !match {
		t.Fatal("expected passwords to match but they did not")
	}
}

func TestCheckPasswordHash_invalid(t *testing.T) {
	hash, err := HashPassword("correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	match, err := CheckPasswordHash("wrongpassword", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error: %v", err)
	}
	if match {
		t.Fatal("expected passwords not to match but they did")
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret"

	tokenString, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	if tokenString == "" {
		t.Fatal("MakeJWT returned empty token")
	}

	parsedID, err := ValidateJWT(tokenString, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}
	if parsedID != userID {
		t.Fatalf("expected user ID %s, got %s", userID, parsedID)
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret"

	tokenString, err := MakeJWT(userID, secret, -time.Second)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(tokenString, secret)
	if err == nil {
		t.Fatal("expected ValidateJWT to reject expired token")
	}
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()

	tokenString, err := MakeJWT(userID, "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(tokenString, "wrong-secret")
	if err == nil {
		t.Fatal("expected ValidateJWT to reject token signed with different secret")
	}
}
