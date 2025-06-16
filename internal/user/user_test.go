package user

import (
	"errors"
	"gophkeeper/internal/mocks"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		expectedError error
	}{
		{
			name:   "Valid token generation",
			userID: "user123",
		},
		{
			name:   "Empty user ID",
			userID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.userID)
			assert.NoError(t, err, "GenerateToken returned an unexpected error")

			parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				return JwtKey, nil
			})

			assert.NoError(t, err, "Failed to parse generated token")
			assert.True(t, parsedToken.Valid, "Generated token is not valid")

			claims, ok := parsedToken.Claims.(*Claims)
			assert.True(t, ok, "Failed to extract claims from token")
			assert.Equal(t, tt.userID, claims.UserID, "UserID in claims does not match expected")
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name           string
		tokenString    string
		expectedClaims *Claims
		expectedError  error
	}{
		{
			name:        "Valid token",
			tokenString: generateTestToken("user123", t),
			expectedClaims: &Claims{
				UserID: "user123",
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: "user-auth",
				},
			},
			expectedError: nil,
		},
		{
			name:           "Invalid token",
			tokenString:    "invalid-token",
			expectedClaims: nil,
			expectedError:  errors.New("invalid token"),
		},
		{
			name:           "Expired token",
			tokenString:    generateExpiredTestToken("user123", t),
			expectedClaims: nil,
			expectedError:  errors.New("invalid token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateToken(tt.tokenString)

			if tt.expectedError != nil {
				assert.Error(t, err, "ValidateToken did not return an expected error")
				assert.Contains(t, err.Error(), tt.expectedError.Error(), "Error message does not match expected")
			} else {
				assert.NoError(t, err, "ValidateToken returned an unexpected error")
			}

			if tt.expectedClaims != nil && claims != nil {
				assert.Equal(t, tt.expectedClaims.UserID, claims.UserID, "UserID in claims does not match expected")
				assert.Equal(t, tt.expectedClaims.Subject, claims.Subject, "Subject in claims does not match expected")
			} else {
				assert.Equal(t, tt.expectedClaims, claims, "Claims do not match expected")
			}
		})
	}
}

func TestNewUserService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	userService := NewUserService(mockStorage)

	assert.NotNil(t, userService, "NewUserService returned nil")
	assert.Equal(t, mockStorage, userService.StorageService, "StorageService does not match expected")
	assert.NotNil(t, userService.cache, "Cache is not initialized")
}

func generateTestToken(userID string, t *testing.T) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "user-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}
	return tokenString
}

func generateExpiredTestToken(userID string, t *testing.T) string {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "user-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		t.Fatalf("failed to generate expired test token: %v", err)
	}
	return tokenString
}
