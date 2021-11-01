package filestore

import "errors"

var ErrNotFound = errors.New("file not found")

// FileStore is an interface to temporarily store files needed by Transports
type FileStore interface {
	// Peek returns the file at the given path without removing it. If the file doesn't exist, the returned error will be ErrNotFound
	// path should be formatted as "id/name". See Put for more details
	Peek(path string) ([]byte, error)
	// Get returns the file at the given path and removes it. If the file doesn't exist, the returned error will be ErrNotFound
	// path should be formatted as "id/name". See Put for more details
	Get(path string) ([]byte, error)
	// Put stores the data in a directory (physical or virtual) with a random id and the given name
	// and returns a path to the file with format id/name.
	// The path can be used by Get to retrieve the file
	Put(name string, data []byte) (string, error)
}
