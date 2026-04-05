package main

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/geirgulbrandsen/chirpy/internal/auth"
	"github.com/geirgulbrandsen/chirpy/internal/database"
	"github.com/google/uuid"
)

type hashedPasswordArg struct {
	plaintext string
}

func (arg hashedPasswordArg) Match(value driver.Value) bool {
	hash, ok := value.(string)
	if !ok || hash == arg.plaintext {
		return false
	}

	match, err := auth.CheckPasswordHash(arg.plaintext, hash)
	return err == nil && match
}

func TestHandlerUpdateUser_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	queries := database.New(db)
	config := &apiConfig{
		dbQueries: queries,
		jwtSecret: "test-secret",
	}

	userID := uuid.New()
	token, err := auth.MakeJWT(userID, config.jwtSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	body := []byte(`{"email":"updated@example.com","password":"new-password"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()

	updatedAt := time.Date(2026, time.April, 5, 12, 30, 0, 0, time.UTC)
	createdAt := updatedAt.Add(-time.Hour)

	mock.ExpectQuery(regexp.QuoteMeta(`-- name: UpdateUserCredentials :one
UPDATE users
SET email = $2,
    hashed_password = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING id, created_at, updated_at, email, hashed_password
`)).
		WithArgs(userID, "updated@example.com", hashedPasswordArg{plaintext: "new-password"}).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "email", "hashed_password"}).
			AddRow(userID, createdAt, updatedAt, "updated@example.com", "stored-hash"))

	config.handlerUpdateUser(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.Code)
	}

	var got userResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("json decode returned error: %v", err)
	}

	if got.ID != userID.String() {
		t.Fatalf("expected id %s, got %s", userID, got.ID)
	}
	if got.Email != "updated@example.com" {
		t.Fatalf("expected email updated@example.com, got %s", got.Email)
	}
	if got.CreatedAt != createdAt.Format("2006-01-02T15:04:05Z") {
		t.Fatalf("expected created_at %s, got %s", createdAt.Format("2006-01-02T15:04:05Z"), got.CreatedAt)
	}
	if got.UpdatedAt != updatedAt.Format("2006-01-02T15:04:05Z") {
		t.Fatalf("expected updated_at %s, got %s", updatedAt.Format("2006-01-02T15:04:05Z"), got.UpdatedAt)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestHandlerUpdateUser_MissingBearerToken(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	config := &apiConfig{
		dbQueries: database.New(db),
		jwtSecret: "test-secret",
	}

	req := httptest.NewRequest(http.MethodPut, "/api/users", bytes.NewReader([]byte(`{"email":"updated@example.com","password":"new-password"}`)))
	resp := httptest.NewRecorder()

	config.handlerUpdateUser(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}

func TestHandlerUpdateUser_MalformedBearerToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	queries := database.New(db)
	config := &apiConfig{
		dbQueries: queries,
		jwtSecret: "test-secret",
	}

	req := httptest.NewRequest(http.MethodPut, "/api/users", bytes.NewReader([]byte(`{"email":"updated@example.com","password":"new-password"}`)))
	req.Header.Set("Authorization", "Token not-a-bearer-token")
	resp := httptest.NewRecorder()

	config.handlerUpdateUser(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestHandlerDeleteChirp_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	config := &apiConfig{
		dbQueries: database.New(db),
		jwtSecret: "test-secret",
	}

	userID := uuid.New()
	chirpID := uuid.New()
	token, err := auth.MakeJWT(userID, config.jwtSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("chirpID", chirpID.String())
	resp := httptest.NewRecorder()

	mock.ExpectQuery(regexp.QuoteMeta(`-- name: GetChirp :one
SELECT id, created_at, updated_at, body, user_id FROM chirps WHERE id = $1
`)).
		WithArgs(chirpID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
			AddRow(chirpID, time.Now().UTC(), time.Now().UTC(), "hello", userID))
	mock.ExpectExec(regexp.QuoteMeta(`-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1
`)).
		WithArgs(chirpID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	config.handlerDeleteChirp(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestHandlerDeleteChirp_ForbiddenForNonAuthor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	config := &apiConfig{
		dbQueries: database.New(db),
		jwtSecret: "test-secret",
	}

	requestUserID := uuid.New()
	authorID := uuid.New()
	chirpID := uuid.New()
	token, err := auth.MakeJWT(requestUserID, config.jwtSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("chirpID", chirpID.String())
	resp := httptest.NewRecorder()

	mock.ExpectQuery(regexp.QuoteMeta(`-- name: GetChirp :one
SELECT id, created_at, updated_at, body, user_id FROM chirps WHERE id = $1
`)).
		WithArgs(chirpID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "body", "user_id"}).
			AddRow(chirpID, time.Now().UTC(), time.Now().UTC(), "hello", authorID))

	config.handlerDeleteChirp(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestHandlerDeleteChirp_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	config := &apiConfig{
		dbQueries: database.New(db),
		jwtSecret: "test-secret",
	}

	userID := uuid.New()
	chirpID := uuid.New()
	token, err := auth.MakeJWT(userID, config.jwtSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("chirpID", chirpID.String())
	resp := httptest.NewRecorder()

	mock.ExpectQuery(regexp.QuoteMeta(`-- name: GetChirp :one
SELECT id, created_at, updated_at, body, user_id FROM chirps WHERE id = $1
`)).
		WithArgs(chirpID).
		WillReturnError(sql.ErrNoRows)

	config.handlerDeleteChirp(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, resp.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestHandlerDeleteChirp_MissingBearerToken(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()

	config := &apiConfig{
		dbQueries: database.New(db),
		jwtSecret: "test-secret",
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+uuid.New().String(), nil)
	req.SetPathValue("chirpID", uuid.New().String())
	resp := httptest.NewRecorder()

	config.handlerDeleteChirp(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.Code)
	}
}
