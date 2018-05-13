package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/yourbasic/bloom"
)

var b *bloom.Filter

type jsonPwned struct {
	Version string        `json:"version"`
	Filter  *bloom.Filter `json:"filter"`
}

const version = "v0.0.0"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	b = bloom.New(502000000, 1000000)

	if loadPath := os.Getenv("FILTER_PATH"); loadPath != "" {
		loadFromFile(loadPath)
	}
	if importPath := os.Getenv("IMPORT_PATH"); importPath != "" {
		importFromFile(importPath)
	}

	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword/", http.HandlerFunc(hashHandler)))
	http.Handle("/save/", http.HandlerFunc(saveHandler))

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func loadFromFile(loadPath string) {
	f, err := os.Open(loadPath)
	if err != nil {
		log.Fatalf("error opening stored filter data from %q: %s", loadPath, err)
	}
	defer f.Close() // ignore error, we were only reading

	decoder := json.NewDecoder(f)
	data := jsonPwned{}
	err = decoder.Decode(&data)
	if err != nil {
		log.Fatalf("error reading stored filter data: %s", err)
	}

	log.Printf("loaded %d entries from %q", data.Filter.Count(), loadPath)

	b = data.Filter
}

func importFromFile(importPath string) {
	f, err := os.Open(importPath)
	if err != nil {
		log.Fatalf("error opening password hashes from %q: %s", importPath, err)
	}
	defer f.Close() // ignore error, we were only reading

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// lines look like: 13c3d0d02ffc0e82abc1dd6b59d441be073d4b15:1
		hashStr := strings.SplitN(scanner.Text(), ":", 1)
		hash, err := hex.DecodeString(hashStr[0])
		if err != nil {
			log.Fatalf("error decoding hex string %q from password hash file: %s", scanner.Text(), err)
		}

		b.AddHash2(hash)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading password hash file: %s", err)
	}

	log.Printf("loaded %d hashed passwords from file %q", b.Count(), importPath)
}

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

	found := b.TestHash2(hashBytes)

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
