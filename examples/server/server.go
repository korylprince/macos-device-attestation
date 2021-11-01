package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	attest "github.com/korylprince/macos-device-attestation"
	"github.com/korylprince/macos-device-attestation/filestore/mem"
	mdm "github.com/korylprince/macos-device-attestation/mdm/micromdm"
	"github.com/korylprince/macos-device-attestation/tokenstore/jwt"
	mdmtransport "github.com/korylprince/macos-device-attestation/transport/mdm"
	"golang.org/x/crypto/pkcs12"
)

var hmackey, _ = base64.StdEncoding.DecodeString("SSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSSDinaQgTWljcm9NRE0gSQ==")

func replyHandler(w http.ResponseWriter, r *http.Request) {
	serial := r.Context().Value(attest.ContextKeySerial)
	j := map[string]string{"msg": fmt.Sprintf("Hello, %s!", serial)}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	e := json.NewEncoder(w)
	e.Encode(j)
}

func main() {
	// read "Apple Developer ID Installer" identity
	identity, err := os.ReadFile("./identity.p12")
	if err != nil {
		log.Fatalln("could not read identity:", err)
	}
	key, cert, err := pkcs12.Decode(identity, "password")
	if err != nil {
		log.Fatalln("could not decode identity:", err)
	}

	m, err := mdm.New("https://mdm.example.com", "dd7755ceb47b4f8bd092b59135f127b1", 10)
	if err != nil {
		log.Fatalln("could not create MDM:", err)
	}

	fs := mem.New(10, time.Minute)
	ts := jwt.New(hmackey, "attest.example.com", []string{"attest.example.com"}, time.Minute*15)

	t := mdmtransport.New(m, "https://mdm.example.com/v1/attest/files", fs, cert, key.(*rsa.PrivateKey))

	as := attest.New(ts, t, fs, log.Default())

	r := mux.NewRouter()
	r.Methods("HEAD", "GET").PathPrefix("/v1/attest/files/").Handler(http.StripPrefix("/v1/attest/files/", as.FileStoreHandler()))
	// you should definitely rate-limit this handler
	r.Methods("POST").Path("/v1/attest/place").Handler(as.PlaceHandler())
	r.Methods("GET").Path("/v1/attest/hello").Handler(as.JSONMiddleware(http.HandlerFunc(replyHandler)))

	// tls is required for macOS to actually install transport pkg
	http.ListenAndServeTLS(":443", "./cert.pem", "./key.pem", r)
}
