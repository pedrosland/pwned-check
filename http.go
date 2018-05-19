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
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	found := h.Filter.TestHash(hashBytes)

	if found {
		w.Write([]byte("oh darn"))
	} else {
		// b.AddHash2(hashBytes)

		w.Write([]byte("you're good for now"))
	}
}
