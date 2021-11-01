package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/korylprince/macos-device-attestation/client"
)

func main() {
	type response struct {
		Code    int    `json:"code"`
		Message string `json:"msg"`
	}

	// it really can take a couple minutes for the payload pkg to get installed
	token, err := client.GetToken("https://mdm.example.com/v1/attest/place", 2*time.Minute)
	if err != nil {
		log.Fatalln("could not get token:", err)
	}

	r, err := http.NewRequest("GET", "https://mdm.example.com/v1/attest/hello", http.NoBody)
	if err != nil {
		log.Fatalln("could not create request:", err)
	}
	client.SetToken(r, token)

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		log.Fatalln("could not perform request:", err)
	}
	defer res.Body.Close()

	resp := new(response)
	d := json.NewDecoder(res.Body)
	if err = d.Decode(resp); err != nil {
		log.Fatalln("could not parse response:", err)
	}

	if resp.Code != 0 {
		log.Fatalln("unexpected code:", resp.Code, http.StatusText(resp.Code))
	}

	fmt.Println("The server said:", resp.Message)
}
