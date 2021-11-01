package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
)

func parseJSON(r *http.Request, v interface{}) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("could not parse Content-Type: %w", err)
	}

	if mediaType != "application/json" {
		return errors.New("Content-Type not application/json")
	}

	dec := json.NewDecoder(r.Body)

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("could not parse request body: %w", err)
	}

	return nil
}

func (s *AttestationService) withJSONResponse(next ReturnHandlerFunc) http.Handler {
	type response struct {
		Code        int    `json:"code"`
		Description string `json:"description"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, body := next(w, r)
		if code == StatusCodeSkip {
			return
		}

		if err, ok := body.(error); ok || body == nil {
			resp := response{Code: code, Description: http.StatusText(code)}
			body = resp
			if err != nil && s.Logger != nil {
				typ := "INFO"
				if code >= http.StatusInternalServerError {
					typ = "ERROR"
				}
				s.Logger.Printf("%s: %v\n", typ, err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)

		e := json.NewEncoder(w)
		err := e.Encode(body)

		if err != nil {
			s.Logger.Println("ERROR: could not encode response:", err)
		}
	})
}
