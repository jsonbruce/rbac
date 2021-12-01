package token

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	defaultExpiration = 24 * time.Hour
	defaultSigningKey = "default-token"
)

// Tokener is an abstract interface for signing and verifying tokens
type Tokener interface {
	// Sign returns the JWT token from a user uuid
	Sign(uuid string) (string, error)

	// Verify returns the user uuid from a JWT token
	Verify(token string) (string, error)
}

type defaultTokener struct {
	SigningKey []byte
}

// NewTokener creates a default token signer
func NewTokener() Tokener {
	return &defaultTokener{
		SigningKey: []byte(defaultSigningKey),
	}
}

func (tk *defaultTokener) Sign(uuid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.StandardClaims{
			Audience:  "audience",
			ExpiresAt: time.Now().Add(defaultExpiration).Unix(),
			Id:        uuid,
			IssuedAt:  time.Now().Unix(),
			Issuer:    "issuer",
			NotBefore: time.Now().Unix(),
			Subject:   "subject",
		})
	return token.SignedString(tk.SigningKey)
}

func (tk *defaultTokener) Verify(tokenString string) (string, error) {
	if len(tokenString) == 0 {
		return "", errors.New("Invalid Token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Invalid SigningMethod")
		}
		return tk.SigningKey, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return "", errors.New("Invalid Token Claims")
	}

	return claims.Id, nil
}
