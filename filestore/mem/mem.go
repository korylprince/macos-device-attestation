package mem

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/korylprince/macos-device-attestation/filestore"
)

const pathSize = 16

// FileStore implements FileStore completely in memory and uses an LRU cache to limit memory usage
type FileStore struct {
	files *ttlcache.Cache
}

// New returns a new FileStore with the given cache size (item count) and item ttl
func New(size int, ttl time.Duration) *FileStore {
	c := ttlcache.NewCache()
	c.SetCacheSizeLimit(size)
	if err := c.SetTTL(ttl); err != nil {
		panic(fmt.Errorf("could not set ttl on cache: %w", err))
	}
	c.SkipTTLExtensionOnHit(true)
	return &FileStore{files: c}
}

// Peek returns the file at the given path without removing it
func (m *FileStore) Peek(path string) ([]byte, error) {
	data, err := m.files.Get(path)
	if errors.Is(err, ttlcache.ErrNotFound) {
		return nil, filestore.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("could not query cache: %w", err)
	}

	return data.([]byte), nil
}

// Get returns the file at the given path and removes it
func (m *FileStore) Get(path string) ([]byte, error) {
	data, err := m.files.Get(path)
	if errors.Is(err, ttlcache.ErrNotFound) {
		return nil, filestore.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("could not query cache: %w", err)
	}

	err = m.files.Remove(path)
	if err != nil && !errors.Is(err, ttlcache.ErrNotFound) {
		return nil, fmt.Errorf("could not remove path: %w", err)
	}

	return data.([]byte), nil
}

// Put stores the data and returns a path with format "<random id>/<name>"
func (m *FileStore) Put(name string, data []byte) (string, error) {
	buf := make([]byte, pathSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate id: %w", err)
	}
	path := fmt.Sprintf("%s/%s", base64.RawURLEncoding.EncodeToString(buf), name)
	if err := m.files.Set(path, data); err != nil {
		return "", fmt.Errorf("could not set path: %w", err)
	}
	return path, nil
}
