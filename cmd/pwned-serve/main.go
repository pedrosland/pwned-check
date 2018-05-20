package main

import (
	"log"
	"net/http"
	"os"

	pwned "github.com/pedrosland/pwned-check"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	loadPath := os.Getenv("FILTER_PATH")
	if loadPath == "" {
		logger.Fatalln("must specify the path to the filter to load in environment variable FILTER_PATH")
	}
	filter := pwned.LoadFilterFromFile(loadPath)

	pwnedHandler := pwned.Handler{Filter: filter, Logger: logger}
	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword", http.HandlerFunc(pwnedHandler.CompatPassword)))
	http.Handle("/pwnedhash/", http.StripPrefix("/pwnedhash", http.HandlerFunc(pwnedHandler.Hash)))

	logger.Printf("starting server on port %s", port)

	logger.Fatal(http.ListenAndServe(":"+port, nil))
}
