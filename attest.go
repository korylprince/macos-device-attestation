package attest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/korylprince/macos-device-attestation/filestore"
	"github.com/korylprince/macos-device-attestation/tokenstore"
	"github.com/korylprince/macos-device-attestation/transport"
)

const pathSize = 16

type ContextKey int

// ContextKeySerial is used to retrieve the serial from an http.Request's context
const ContextKeySerial ContextKey = iota

// StatusCodeSkip is returned by a ReturnHandlerFunc to indicate the ResponseWriter should not be written to
const StatusCodeSkip int = -1

// AttestationService is an HTTP service to allow a macOS client to attest that it has root access on a device with a particular serial number
type AttestationService struct {
	tokenstore.TokenStore
	transport.Transport
	filestore.FileStore
	*log.Logger
}

// New returns a new AttestationService
func New(tokenStore tokenstore.TokenStore, transport transport.Transport, fileStore filestore.FileStore, logger *log.Logger) *AttestationService {
	return &AttestationService{TokenStore: tokenStore, Transport: transport, FileStore: fileStore, Logger: logger}
}

// ReturnHandlerFunc returns an HTTP status code and body for the given request. If the returned code is StatusCodeSkip, the ResponseWriter should not be written to by the caller
type ReturnHandlerFunc func(w http.ResponseWriter, r *http.Request) (int, interface{})

func (s *AttestationService) placeReturnHandlerFunc(w http.ResponseWriter, r *http.Request) (int, interface{}) {
	type request struct {
		Serial string `json:"serial"`
	}

	type response struct {
		Path string `json:"path"`
	}

	req := new(request)
	if err := parseJSON(r, req); err != nil {
		return http.StatusBadRequest, fmt.Errorf("attest place: could not parse request: %w", err)
	}

	if req.Serial == "" {
		return http.StatusBadRequest, errors.New("attest place: empty serial")
	}

	token, err := s.TokenStore.New(req.Serial)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("attest place: could not create token: %w", err)
	}

	p := make([]byte, pathSize)
	if _, err := rand.Read(p); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("attest place: could not generate path: %w", err)
	}

	path := fmt.Sprintf("/tmp/%s", base64.RawURLEncoding.EncodeToString(p))

	if err := s.Transport.Place(token, req.Serial, path); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("attest place: could not place token: %w", err)
	}

	return http.StatusOK, &response{Path: path}
}

// PlaceHandler is a token placing http.Handler. PlaceHandler should be mounted to a URL that's called by an attestation client
func (s *AttestationService) PlaceHandler() http.Handler {
	return s.withJSONResponse(s.placeReturnHandlerFunc)
}

// FileStoreHandler is a file handler. If the handler is not mounted at "/", then it should be wrapped in http.StripPrefix so the handler sees the request rooted at /
func (s *AttestationService) FileStoreHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		var (
			file []byte
			err  error
		)
		if r.Method == http.MethodHead {
			file, err = s.FileStore.Peek(path)
		} else {
			file, err = s.FileStore.Get(path)
		}

		if err != nil {
			if errors.Is(err, filestore.ErrNotFound) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("404 Not Found"))
				return
			}
			if s.Logger != nil {
				s.Logger.Printf("ERROR: %v\n", err)
			}

			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			return
		}

		http.ServeContent(w, r, "payload.pkg", time.Now(), bytes.NewReader(file))
	})
}

// Middleware is a middleware that checks that a valid attestation token has been sent in the Authorization header, and sets the corresponding serial in the request's context. Middleware returns a ReturnHandlerFunc and is intended to be wrapped by an http.Handler that will handle the returned status code and error. See ReturnHandlerFunc for more information. JSONMiddleware is a pre-built handler that marshals the code and error as JSON.
func (s *AttestationService) Middleware(next http.Handler) ReturnHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) (int, interface{}) {
		header := strings.Split(r.Header.Get("Authorization"), " ")

		if len(header) != 2 || header[0] != "Bearer" {
			return http.StatusBadRequest, errors.New("attest middleware: invalid header")
		}
		token := header[1]
		serial, err := s.TokenStore.Authenticate(token)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("attest middleware: could not get serial: %w", err)
		}

		ctx := context.WithValue(r.Context(), ContextKeySerial, serial)

		next.ServeHTTP(w, r.WithContext(ctx))
		return StatusCodeSkip, nil
	}
}

// JSONMiddleware is a wrapper for Middleware that returns errors encountered back to the client in JSON format. e.g. {"code":401,"description":"Bad Request"}
func (s *AttestationService) JSONMiddleware(next http.Handler) http.Handler {
	return s.withJSONResponse(s.Middleware(next))
}
