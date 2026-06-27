package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"domains-exporter/internal/cache"
	"domains-exporter/internal/probe"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	listenAddr   = flag.String("web.listen-address", ":9222", "Address to listen on for HTTP requests")
	cacheTTL     = flag.Duration("cache-ttl", 3*time.Hour, "Cache TTL for WHOIS results")
	whoisTimeout = flag.Duration("whois-timeout", 10*time.Second, "Timeout for WHOIS queries")
	logLevel     = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Setup logger
	var logger *zap.Logger
	var err error

	switch *logLevel {
	case "debug":
		logger, err = zap.NewDevelopment()
	case "info", "warn", "error":
		config := zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(parseLogLevel(*logLevel))
		logger, err = config.Build()
	default:
		config := zap.NewProductionConfig()
		logger, err = config.Build()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1) // nolint:gocritic
	}
	defer func() {
		_ = logger.Sync()
	}()

	logger.Info("domains-exporter starting",
		zap.String("listen_address", *listenAddr),
		zap.Duration("cache_ttl", *cacheTTL),
		zap.Duration("whois_timeout", *whoisTimeout),
	)

	// Create cache
	c := cache.New(*cacheTTL)
	defer c.Close()

	// Create probe handler
	probeHandler := probe.NewHandler(c, *whoisTimeout, logger)

	// Setup HTTP routes
	http.HandleFunc("/", landingPageHandler)
	http.Handle("/probe", probeHandler)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", healthzHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("listening for HTTP requests", zap.String("address", *listenAddr))
		serverErrors <- server.ListenAndServe()
	}()

	// Wait for interrupt signal or server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server error", zap.Error(err))
		}
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.Stringer("signal", sig))

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := server.Shutdown(ctx)
		cancel()

		if shutdownErr != nil {
			logger.Error("graceful shutdown failed", zap.Error(shutdownErr))
			os.Exit(1) // nolint:gocritic
		}

		logger.Info("server shutdown successfully")
	}
}

func landingPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>domains-exporter</title>
    <style>
        body { font-family: sans-serif; margin: 40px; }
        h1 { color: #333; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .endpoint { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>domains-exporter</h1>
    <p>A Prometheus exporter for monitoring domain expiration dates.</p>
    <div class="endpoint">
        <h3><code>/probe?target=&lt;domain&gt;</code></h3>
        <p>Probe a domain for expiration information. Optional parameters:</p>
        <ul>
            <li><code>target</code> (required): Domain name to probe</li>
            <li><code>server</code> (optional): Custom WHOIS server address</li>
        </ul>
        <p>Example: <a href="/probe?target=example.com">/probe?target=example.com</a></p>
    </div>
    <div class="endpoint">
        <h3><code>/metrics</code></h3>
        <p>Exporter internal metrics (Go runtime, total probes, cache size, etc.)</p>
        <p><a href="/metrics">/metrics</a></p>
    </div>
    <div class="endpoint">
        <h3><code>/healthz</code></h3>
        <p>Health check endpoint</p>
        <p><a href="/healthz">/healthz</a></p>
    </div>
</body>
</html>`)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func parseLogLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
