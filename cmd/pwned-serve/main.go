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

	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword", pwned.Handler{Filter: filter, Logger: logger}))

	logger.Printf("starting server on port %s", port)

	logger.Fatal(http.ListenAndServe(":"+port, nil))
}
