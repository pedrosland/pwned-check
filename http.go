package pwned

import (
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strings"
)

// Handler implements ServeHTTP
type Handler struct {
	Filter *Filter
	Logger *log.Logger
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if found {
		io.WriteString(w, "1") // We only know if it exists or not
	} else {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "OK")
	}
}
