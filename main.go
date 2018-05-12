package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword/", http.HandlerFunc(passwdHandler)))

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func passwdHandler(w http.ResponseWriter, r *http.Request) {
	pwd := strings.TrimSuffix(r.URL.Path, "/")

	if pwd == "" {
		http.NotFound(w, r)
		return
	}

	log.Print(pwd)
	w.Write([]byte("hi"))
}
