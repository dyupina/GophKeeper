package user

import (
	"errors"
	"time"

	"gophkeeper/internal/storage"

	"github.com/golang-jwt/jwt/v5"
)

// User manages user authentication and authorization.
type User struct {
	StorageService storage.StorageService
	cache          map[string]time.Time
	Login          string `json:"login"`
	Password       string `json:"password"`
}

type UserService interface {
}

// JwtKey is the secret key used for signing and validating JWTs.
var JwtKey = []byte("your-secret-key")

// Claims defines the structure for JWT claims.
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateToken creates a JWT for the given user ID.
func GenerateToken(userID string) (string, error) {
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Токен действителен 24 часа
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "user-auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtKey)
}

// ValidateToken validates a JWT and extracts its claims.
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}

// NewUserService creates a new instance of User.
func NewUserService(storage storage.StorageService) *User {
	return &User{
		StorageService: storage,
		cache:          make(map[string]time.Time),
	}
}
