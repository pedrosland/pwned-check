package pwned

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strings"
)

// MetricFunc is a function to record metrics.
// The first argument is the handler (password or hash).
// The second argument is in_list.
type MetricFunc func(string, bool)

// Handler provides HTTP HandlerFuncs
type Handler struct {
	Filter     *Filter
	Logger     *log.Logger
	MetricFunc MetricFunc
}

const newLine = "\n"

// CompatPassword provides compatibility with the currently deprecated
// Have I Been Pwned API (https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByPassword)
// except that it only supports already hashed passwords at present.
func (h Handler) CompatPassword(w http.ResponseWriter, r *http.Request) {
	hash := strings.Trim(r.URL.Path, "/")

	if hash == "" {
		http.NotFound(w, r)
		return
	}

	if len(hash) != 40 {
		msg := "expected hexadecimal encoded sha1 string of 40 characters"
		h.Logger.Println(msg)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, msg)
		return
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Expected hexadecimal encoded sha1 string")
		h.Logger.Printf("error decoding hex string %q: %s", hash, err)
		return
	}

	found := h.Filter.TestHash(hashBytes)
	if h.MetricFunc != nil {
		h.MetricFunc("password", found)
	}

	if found {
		io.WriteString(w, "1\n") // We only know if it exists or not
	} else {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "OK\n")
	}
}

// Hash implements HandlerFunc and provides a JSON API for pwned hashes.
func (h Handler) Hash(w http.ResponseWriter, r *http.Request) {
	hash := strings.Trim(r.URL.Path, "/")

	if hash == "" {
		http.NotFound(w, r)
		return
	}

	if len(hash) != 40 {
		msg := "expected hexadecimal encoded sha1 string of 40 characters"
		h.Logger.Println(msg)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, msg)
		return
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Expected hexadecimal encoded sha1 string")
		h.Logger.Printf("error decoding hex string %q: %s", hash, err)
		return
	}

	found := h.Filter.TestHash(hashBytes)
	if h.MetricFunc != nil {
		h.MetricFunc("hash", found)
	}
	w.Header().Set("Content-Type", "application/json")

	if found {
		io.WriteString(w, `{"in_list": "probably"}`+newLine)
	} else {
		io.WriteString(w, `{"in_list": "no"}`+newLine)
	}
}
