package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/korylprince/macos-device-attestation/tokenstore"
)

// TokenStore implements a stateless TokenStore using JWTs
type TokenStore struct {
	key []byte
	iss string
	aud []string
	dur time.Duration
}

// New returns a new JWT TokenStore. key should be 256 bits. If iss and aud are set, they will be put in the token and verified by Authenticate. dur is used to set the iat, nbf, and exp claims
func New(key []byte, iss string, aud []string, dur time.Duration) *TokenStore {
	return &TokenStore{key: key, iss: iss, aud: aud, dur: dur}
}

// New generates a new token for identifier
func (t *TokenStore) New(identifier string) (token string, err error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    t.iss,
		Audience:  t.aud,
		Subject:   identifier,
		IssuedAt:  &jwt.NumericDate{Time: time.Now()},
		NotBefore: &jwt.NumericDate{Time: time.Now().Add(-time.Second * 15)}, // allow small time drift
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(t.dur)},
	})

	token, err = tok.SignedString(t.key)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %w", err)
	}

	return token, nil
}

// Authenticate authenticates the token and returns the associated identifier.
func (t *TokenStore) Authenticate(token string) (identifier string, err error) {
	claims := make(jwt.MapClaims)
	_, err = jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		// validate alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", token.Header["alg"])
		}

		return t.key, nil
	})
	if err != nil {
		return "", &tokenstore.InvalidTokenError{Err: fmt.Errorf("could not parse token: %w", err)}
	}

	if err = claims.Valid(); err != nil {
		return "", &tokenstore.InvalidTokenError{Err: fmt.Errorf("token is expired: %w", err)}
	}

	if !claims.VerifyIssuer(t.iss, t.iss == "") {
		return "", &tokenstore.InvalidTokenError{Err: fmt.Errorf("invalid issuer: %s", claims["iss"])}
	}

	if len(t.aud) == 0 {
		return claims["sub"].(string), nil
	}

	for _, a := range t.aud {
		if claims.VerifyAudience(a, true) {
			return claims["sub"].(string), nil
		}
	}

	return "", &tokenstore.InvalidTokenError{Err: fmt.Errorf("invalid audience: %v", claims["aud"])}
}
