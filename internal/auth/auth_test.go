package auth

import "testing"

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
