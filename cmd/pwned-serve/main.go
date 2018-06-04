package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pwned "github.com/pedrosland/pwned-check"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	loadPath := os.Getenv("FILTER_PATH")
	if loadPath == "" {
		logger.Fatalln("must specify the path to the filter to load in environment variable FILTER_PATH")
	}

	server := http.Server{
		Addr: ":" + port,
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigs
		logger.Println("shutting down")
		cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		cancel()
		logger.Println("graceful shutdown complete")
	}()

	filter := pwned.LoadFilterFromFile(ctx, loadPath)
	cancel() // free resources

	pwnedHandler := pwned.Handler{Filter: filter, Logger: logger}
	http.Handle("/pwnedpassword/", http.StripPrefix("/pwnedpassword", http.HandlerFunc(pwnedHandler.CompatPassword)))
	http.Handle("/pwnedhash/", http.StripPrefix("/pwnedhash", http.HandlerFunc(pwnedHandler.Hash)))
	http.HandleFunc("/healthz", health)

	logger.Printf("starting server on port %s", port)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		logger.Fatal(err)
	}
}

func health(w http.ResponseWriter, r *http.Request) {
	// The only right value for this is OK. When the filter is being loaded, the
	// HTTP server isn't alive. When the HTTP server is shutting down, new connections
	// aren't accepted.
	io.WriteString(w, "OK\n")
}
