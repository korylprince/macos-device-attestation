package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/korylprince/macserial"
)

// GetToken retrieves a token from the device attestation service. GetToken will retry with exponential backoff until timeout
func GetToken(url string, timeout time.Duration) (string, error) {
	type request struct {
		Identifier string `json:"identifier"`
	}

	type response struct {
		Path string `json:"path"`
	}

	serial, err := macserial.Get()
	if err != nil {
		return "", fmt.Errorf("could not get serial: %w", err)
	}
	if serial == "" {
		return "", fmt.Errorf("could not get serial: %w", errors.New("serial is empty"))
	}

	req, err := json.Marshal(&request{Identifier: serial})
	if err != nil {
		return "", fmt.Errorf("could not marshal request: %w", err)
	}

	res, err := http.Post(url, "application/json", bytes.NewBuffer(req))
	if err != nil {
		return "", fmt.Errorf("could not perform request: %w", err)
	}
	defer res.Body.Close()

	resp := new(response)
	d := json.NewDecoder(res.Body)
	if err = d.Decode(resp); err != nil {
		return "", fmt.Errorf("could not parse response: %w", err)
	}

	// wait initially for token to be placed
	time.Sleep(5 * time.Second)

	// try to get token with exponential backoff
	var token string
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	b.MaxElapsedTime = timeout

	if err = backoff.Retry(func() error {
		buf, err := os.ReadFile(resp.Path)
		if err != nil {
			return fmt.Errorf("could not read token file: %w", err)
		}
		if len(buf) == 0 {
			return fmt.Errorf("could not read token file: %w", errors.New("token file empty"))
		}
		token = string(buf)
		return nil
	}, b); err != nil {
		return "", fmt.Errorf("could not get token: %w", err)
	}

	return token, nil
}

// SetToken will set the Authorization header for a request
func SetToken(r *http.Request, token string) {
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
}
