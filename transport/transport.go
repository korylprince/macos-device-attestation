package transport

// Transport is an interface for securely transporting and placing a secure token at a specified location on a macOS device.
// Implementers should take care to make sure the token is never readable by non-root users, both during transport and once written to disk
type Transport interface {
	// Place places the token at path on the device identified by identifier
	Place(token, identifier, path string) error
}
