// Package probe provides the HTTP handler for domain expiration probes.
package probe

import (
	"net/http"
	"strings"
	"time"

	"domains-exporter/internal/cache"
	"domains-exporter/internal/whois"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Handler manages domain probe requests.
type Handler struct {
	cache        *cache.Cache
	timeout      time.Duration
	logger       *zap.Logger
	registry     prometheus.Registerer
	totalProbes  prometheus.Counter
	failedProbes prometheus.Counter
	cachedProbes prometheus.Counter
}

// NewHandler creates a new probe handler.
func NewHandler(c *cache.Cache, timeout time.Duration, logger *zap.Logger) *Handler {
	return NewHandlerWithRegistry(c, timeout, logger, prometheus.DefaultRegisterer)
}

// NewHandlerWithRegistry creates a new probe handler with a custom registry.
func NewHandlerWithRegistry(c *cache.Cache, timeout time.Duration, logger *zap.Logger, registry prometheus.Registerer) *Handler {
	factory := promauto.With(registry)

	return &Handler{
		cache:    c,
		timeout:  timeout,
		logger:   logger,
		registry: registry,
		totalProbes: factory.NewCounter(prometheus.CounterOpts{
			Name: "domain_exporter_probes_total",
			Help: "Total number of domain probes performed",
		}),
		failedProbes: factory.NewCounter(prometheus.CounterOpts{
			Name: "domain_exporter_probes_failed_total",
			Help: "Total number of failed domain probes",
		}),
		cachedProbes: factory.NewCounter(prometheus.CounterOpts{
			Name: "domain_exporter_probes_cached_total",
			Help: "Total number of probes served from cache",
		}),
	}
}

// ServeHTTP handles HTTP requests to /probe.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.totalProbes.Inc()

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target query parameter is required", http.StatusBadRequest)
		return
	}

	// Sanitize domain name
	target = strings.ToLower(strings.TrimSpace(target))

	// Optional custom WHOIS server
	whoisServer := r.URL.Query().Get("server")

	// Try to get from cache first
	var result *cache.Entry
	var fromCache bool

	if entry, ok := h.cache.Get(target); ok {
		result = entry
		fromCache = true
		h.cachedProbes.Inc()
		h.logger.Debug("cache hit", zap.String("domain", target))
	} else {
		// Perform WHOIS lookup
		lookupResult := whois.Lookup(target, whoisServer, h.timeout, h.logger)
		result = &cache.Entry{
			ExpirationTime: lookupResult.ExpirationTime,
			Success:        lookupResult.Success,
			Error:          lookupResult.Error,
		}

		if !lookupResult.Success {
			h.failedProbes.Inc()
		}

		// Cache the result
		h.cache.Set(target, result)

		h.logger.Debug("cache miss, performed lookup", zap.String("domain", target), zap.Bool("success", result.Success))
	}

	// Create a per-request registry for this probe
	registry := prometheus.NewRegistry()

	// Create metrics for this probe
	probeSuccess := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "domain_probe_success",
		Help: "Whether the domain probe was successful",
	})

	probeDuration := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "domain_probe_duration_seconds",
		Help: "Duration of the domain probe in seconds",
	})

	expirationTimestamp := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "domain_expiration_timestamp_seconds",
		Help: "Unix timestamp of domain expiration",
	})

	secondsRemaining := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "domain_expiration_seconds_remaining",
		Help: "Seconds until domain expiration (negative if expired)",
	})

	probeCached := promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "domain_probe_cached",
		Help: "Whether the result was served from cache",
	})

	// Populate metrics
	if result.Success {
		probeSuccess.Set(1)
		expirationTimestamp.Set(float64(result.ExpirationTime.Unix()))

		remaining := time.Until(result.ExpirationTime).Seconds()
		secondsRemaining.Set(remaining)
	} else {
		probeSuccess.Set(0)
	}

	probeDuration.Set(result.CachedDuration.Seconds())

	if fromCache {
		probeCached.Set(1)
	} else {
		probeCached.Set(0)
	}

	// Encode the response
	h.encodeMetrics(w, registry)
}

// encodeMetrics writes metrics in Prometheus text format.
func (h *Handler) encodeMetrics(w http.ResponseWriter, registry *prometheus.Registry) {
	encoder := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	encoder.ServeHTTP(w, &http.Request{
		Header: make(http.Header),
	})
}
