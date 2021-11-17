package micromdm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	lru "github.com/hashicorp/golang-lru"
	macospkg "github.com/korylprince/go-macos-pkg"
	attest "github.com/korylprince/macos-device-attestation"
)

// MDM implements the MDM interface. The interface has a configurable cache for serial-to-UDID lookups
type MDM struct {
	// URLPrefix is the prefix for MDM without the trailing slash, e.g. https://mdm.example.com
	URLPrefix string
	Token     string
	cache     *lru.TwoQueueCache
}

// New returns new MDM with the given parameters. size is the size (number of items) of the cache.
func New(prefix, token string, size int) (*MDM, error) {
	cache, err := lru.New2Q(size)
	if err != nil {
		return nil, fmt.Errorf("could not create cache: %w", err)
	}

	return &MDM{URLPrefix: prefix, Token: token, cache: cache}, nil
}

// Transform returns the UDID for the given serial. If the serial is not found, attest.ErrInvalidIdentifier is returned
func (m *MDM) Transform(serial string) (string, error) {
	type response struct {
		Devices []struct {
			UDID string `json:"udid"`
		} `json:"devices"`
		Error string `json:"error"`
	}

	if udid, ok := m.cache.Get(serial); ok {
		return udid.(string), nil
	}

	q := map[string]interface{}{
		"filter_serial": []string{serial},
	}

	j, err := json.Marshal(q)
	if err != nil {
		return "", fmt.Errorf("could not marshal query: %w", err)
	}

	r, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/devices", m.URLPrefix), bytes.NewBuffer(j))
	if err != nil {
		return "", fmt.Errorf("could not create request: %w", err)
	}
	r.SetBasicAuth("micromdm", m.Token)

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", fmt.Errorf("could not complete request: %w", err)
	}
	defer res.Body.Close()

	resp := new(response)
	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(resp); err != nil {
		return "", fmt.Errorf("could not parse response: %w", err)
	}

	if resp.Error != "" {
		return "", fmt.Errorf("could not query devices: %s", resp.Error)
	}

	if len(resp.Devices) != 1 || resp.Devices[0].UDID == "" {
		return "", attest.ErrInvalidIdentifier
	}

	m.cache.Add(serial, resp.Devices[0].UDID)

	return resp.Devices[0].UDID, nil
}

// InstallEnterpriseApplication runs the InstallEnterpriseApplication command with the given udid and manifest
func (m *MDM) InstallEnterpriseApplication(udid string, manifest *macospkg.Manifest) error {
	type response struct {
		Error string `json:"error"`
	}

	cmd := map[string]interface{}{
		"request_type": "InstallEnterpriseApplication",
		"udid":         udid,
		"manifest":     manifest,
	}

	j, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("could not marshal command: %w", err)
	}

	r, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/commands", m.URLPrefix), bytes.NewBuffer(j))
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	r.SetBasicAuth("micromdm", m.Token)

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("could not complete request: %w", err)
	}
	defer res.Body.Close()

	resp := new(response)
	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(resp); err != nil {
		return fmt.Errorf("could not parse response: %w", err)
	}

	if resp.Error != "" {
		return fmt.Errorf("could not execute command: %s", resp.Error)
	}

	return nil
}
