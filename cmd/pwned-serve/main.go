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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	filterCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pwned_password_checks_total",
			Help: "A counter for pwned password checks.",
		},
		[]string{"handler", "in_list"},
	)

	// duration is partitioned by the HTTP method and handler. It uses custom
	// buckets based on the expected request duration.
	reqDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_api_request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"handler", "method"},
	)

	reqCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_api_requests_total",
			Help: "A counter for HTTP requests.",
		},
		[]string{"code", "handler"},
	)
)

func init() {
	prometheus.MustRegister(filterCounter, reqDuration, reqCounter)
}

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

	pwnedHandler := pwned.Handler{Filter: filter, Logger: logger, MetricFunc: metricFunc}
	passwdHandler := promhttp.InstrumentHandlerDuration(reqDuration.MustCurryWith(prometheus.Labels{"handler": "pwnedpassword"}),
		promhttp.InstrumentHandlerCounter(reqCounter.MustCurryWith(prometheus.Labels{"handler": "pwnedpassword"}),
			http.StripPrefix("/pwnedpassword", http.HandlerFunc(pwnedHandler.CompatPassword)),
		))
	hashHandler := promhttp.InstrumentHandlerDuration(reqDuration.MustCurryWith(prometheus.Labels{"handler": "pwnedhash"}),
		promhttp.InstrumentHandlerCounter(reqCounter.MustCurryWith(prometheus.Labels{"handler": "pwnedhash"}),
			http.StripPrefix("/pwnedhash", http.HandlerFunc(pwnedHandler.Hash)),
		))

	http.Handle("/pwnedpassword/", passwdHandler)
	http.Handle("/pwnedhash/", hashHandler)
	http.Handle("/metrics", promhttp.Handler())
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

func metricFunc(handlerName string, inList bool) {
	inListStr := "false"
	if inList {
		inListStr = "true"
	}
	filterCounter.WithLabelValues(handlerName, inListStr).Inc()
}
