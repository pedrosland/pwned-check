package main

import (
	"log"
	"net/http"
	"os"

	pwned "github.com/pedrosland/pwned-check"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	loadPath := os.Getenv("FILTER_PATH")
	if loadPath == "" {
		log.Fatalln("must specify the path to the filter to load in environment variable FILTER_PATH")
	}
	filter := pwned.LoadFilterFromFile(loadPath)

	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword/", pwned.Handler{Filter: filter}))

	log.Printf("starting server on port %s", port)

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
