package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var (
	proxyListen      = flag.String("listen", "127.0.0.1:8086", "Host and port to listen on")
	proxyEndpoint    = flag.String("endpoint", "localhost:8086", "Endpoint to return via /cookie")
	proxyExpires     = flag.Int("expires", 20, "session token expiration time (in seconds)")
	secretString     = []byte(os.Getenv("SECRET"))
	secretBytes      []byte
	proxyEndpointB64 string
)

func main() {
	flag.Parse()
	proxyEndpointB64 = base64.URLEncoding.EncodeToString([]byte("{\"endpoint\":\"" + *proxyEndpoint + "\"}"))

	if len(secretString) == 0 {
		secretBytes = make([]byte, 32)
		if n, err := rand.Read(secretBytes); err != nil && n != 32 {
			panic("random was unable to generate secret")
		}
	} else {
		res := sha256.Sum256(secretString)
		secretBytes = res[:]
	}

	r := mux.NewRouter()
	r.HandleFunc("/cookie", getCookie).Methods("GET")
	r.HandleFunc("/proxy", getProxySession).Methods("GET")
	r.HandleFunc("/connect", wsConnect)

    log.Println("Server listening on "+ *proxyListen)
	log.Fatal(http.ListenAndServe(*proxyListen, r))
}
