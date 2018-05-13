package main

import (
	"log"
	"net/http"
	"os"
)

var b *Filter

type jsonPwned struct {
	Version string  `json:"version"`
	Filter  *Filter `json:"filter"`
}

const version = "v0.0.0"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	b = NewFilter(502000000, 1000000)

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
