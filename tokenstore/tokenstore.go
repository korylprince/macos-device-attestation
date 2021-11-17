package tokenstore

import "fmt"

// TokenStore is an interface to generate and authenticate tokens associated with device identifiers
type TokenStore interface {
	// New generates a new token for identifier
	New(identifier string) (token string, err error)
	// Authenticate authenticates the token and returns the associated identifier. If token is invalid, err will be of type InvalidTokenError
	Authenticate(token string) (identifier string, err error)
}

type InvalidTokenError struct {
	Err error
}

func (e *InvalidTokenError) Error() string {
	return fmt.Sprintf("invalid token: %v", e.Err)
}

func (e *InvalidTokenError) Unwrap() error {
	return e.Err
}
