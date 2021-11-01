package mem

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/korylprince/macos-device-attestation/tokenstore"
)

const tokenSize = 32

// TokenStore implements TokenStore completely in memory and uses an LRU cache to limit memory usage
type TokenStore struct {
	tokens *ttlcache.Cache
}

// New returns a new TokenStore with the given cache size (item count) and item ttl
func New(size int, ttl time.Duration) *TokenStore {
	c := ttlcache.NewCache()
	c.SetCacheSizeLimit(size)
	if err := c.SetTTL(ttl); err != nil {
		panic(fmt.Errorf("could not set ttl on cache: %w", err))
	}
	c.SkipTTLExtensionOnHit(true)
	return &TokenStore{tokens: c}
}

// New generates a new token for the given serial
func (t *TokenStore) New(serial string) (token string, err error) {
	tok := make([]byte, tokenSize)
	if _, err := rand.Read(tok); err != nil {
		return "", fmt.Errorf("could not generate token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(tok)

	if err := t.tokens.Set(token, serial); err != nil {
		return "", fmt.Errorf("could not set token: %w", err)
	}
	return token, nil
}

// Authenticate authenticates the token and returns the associated serial number
func (t *TokenStore) Authenticate(token string) (serial string, err error) {
	ser, err := t.tokens.Get(token)
	if errors.Is(err, ttlcache.ErrNotFound) {
		return "", &tokenstore.InvalidTokenError{Err: ttlcache.ErrNotFound}
	}
	if err != nil {
		return "", fmt.Errorf("could not query cache: %w", err)
	}

	return ser.(string), nil
}
