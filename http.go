package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func hashHandler(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimSuffix(r.URL.Path, "/")

	if hash == "" {
		http.NotFound(w, r)
		return
	}

	if len(hash) != 40 {
		msg := "expected hexadecimal encoded sha1 string of 40 characters"
		log.Println(msg)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, msg)
		return
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Expected hexadecimal encoded sha1 string")
		log.Printf("error decoding hex string %q: %s", hash, err)
	}

	found := b.TestHash(hashBytes)

	if found {
		w.Write([]byte("oh darn"))
	} else {
		// b.AddHash2(hashBytes)

		w.Write([]byte("you're good for now"))
	}
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	f, err := os.Create("pwned-data.json")
	if err != nil {
		log.Printf("error opening data file to write: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "Error")
		return
	}

	data := jsonPwned{
		Filter:  b,
		Version: version,
	}

	encoder := json.NewEncoder(f)
	err = encoder.Encode(&data)
	if err != nil {
		log.Printf("error writing data to file: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "Error")
		return
	}

	err = f.Close()
	if err != nil {
		log.Printf("error closing file: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "Error")
		return
	}

	io.WriteString(w, "OK")
}
