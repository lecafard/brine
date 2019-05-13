package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	mss              = 32 * 1024
	maxAck           = 16777216 // 2^24
	randLength       = 8
)

var (
	proxyErrorVersion = base64.URLEncoding.EncodeToString([]byte("{\"error\":\"incorrect endpoint version.\"}"))
	upgrader          = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: handshakeTimeout,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

type sessionID struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	Expires int64  `json:"expires"`
	Nonce   uint16 `json:"nonce"`
}

func getCookie(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ext := query.Get("ext")
	path := query.Get("path")
	version := query.Get("version")

	if ext == "" || path == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Either ext and/or path are not defined."))
		return
	}

	if version != "" && version != "2" {
		http.Redirect(w, r, "chrome-extension://"+ext+"/"+path+"#"+proxyErrorVersion, http.StatusFound)
		return
	}

	cookie := &http.Cookie{Name: "cors-origin", Value: "chrome-extension://" + ext, HttpOnly: true}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "chrome-extension://"+ext+"/"+path+"#"+proxyEndpointB64, http.StatusFound)

}

func getProxySession(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	host := query.Get("host")
	portS := query.Get("port")

	if port, err := strconv.Atoi(portS); err != nil || port <= 0 || port > 65535 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("port is not a valid number"))
		return
	}

	// lots of security issues to fix
	// use cookies to store origin
	origin, err := r.Cookie("cors-origin")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid origin from /cookie."))
		return
	}

	w.Header().Set("access-control-allow-origin", origin.Value)
	w.Header().Set("access-control-allow-credentials", "true")
	w.WriteHeader(http.StatusOK)

	token := sessionID{
		Host:    host,
		Port:    portS,
		Expires: time.Now().Unix() + int64(*proxyExpires),
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		log.Println("sessionID token not valid")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	randBytes := make([]byte, randLength)
	if n, err := rand.Read(randBytes); err != nil && n != randLength {
		log.Println("not enough random bytes")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	retBytes := append(randBytes, tokenJSON...)
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write(retBytes)

	// generate base64 with [HMAC][Nonce][{host, port, expires}]
	w.Write([]byte(base64.URLEncoding.EncodeToString(append(mac.Sum(nil), retBytes...))))
}

func wsConnect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var readAck uint32
	var writeAck uint32

	// get session id
	query := r.URL.Query()
	sid := query.Get("sid")
	if sid == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid session id."))
		return
	}

	// validate session id
	sidBytes, err := base64.URLEncoding.DecodeString(sid)
	if err != nil || len(sidBytes) < 32+randLength {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid session id."))
		return
	}

	// validating mac of payload
	mac, payload := sidBytes[:32], sidBytes[32:]
	newMac := hmac.New(sha256.New, secretBytes)
	newMac.Write(payload)
	if !bytes.Equal(newMac.Sum(nil), mac) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid session id."))
		return
	}

	token := sessionID{}
	if err := json.Unmarshal(payload[randLength:], &token); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("payload decode error."))
		return
	}

	if token.Expires < time.Now().Unix() {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("session token expired."))
		return
	}

	log.Println("opening session to " + token.Host + " on port " + token.Port)

	// open websocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("error upgrading websocket.", err)
		return
	}
	defer ws.Close()

	// open socket on host side
	s, err := net.DialTimeout("tcp", net.JoinHostPort(token.Host, token.Port), dialTimeout)
	if err != nil {
		log.Println("error opening socket on host.", err)
		return
	}
	defer s.Close()

	// reading from ws and sending to socket
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}

			mt, b, err := ws.ReadMessage()
			if err != nil || mt == websocket.CloseMessage {
				cancel()
				return
			}

			if mt == websocket.CloseMessage {
				cancel()
				log.Println("closing session to " + token.Host + " on port " + token.Port)
				return
			} else if mt != websocket.BinaryMessage {
				continue
			}

			if len(b) < 4 {
				log.Println("ws packet format error, less than 4 bytes read.")
				cancel()
				return
			}
			if binary.BigEndian.Uint32(b[:4]) > readAck {
				log.Println("invalid readAck")
				cancel()
				return
			}

			writeAck += uint32(len(b) - 4)
			writeAck %= maxAck
			if _, err = s.Write(b[4:]); err != nil {
				log.Println("error in s.write", err)
				cancel()
				return
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		b := make([]byte, mss-4)
		nBytes, err := s.Read(b)

		if err != nil {
			log.Println("error in s.read", err)
			cancel()
			return
		}

		readAck += uint32(nBytes)
		readAck %= maxAck

		rab := make([]byte, 4)
		binary.BigEndian.PutUint32(rab, writeAck)

		if err := ws.WriteMessage(websocket.BinaryMessage, append(rab, b[:nBytes]...)); err != nil {
			log.Println("error in wsw.write", err)
			cancel()
			return
		}
	}
}
