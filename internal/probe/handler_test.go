package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"domains-exporter/internal/cache"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func TestProbeHandler_MissingTarget(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	c := cache.New(3 * time.Hour)
	defer c.Close()

	registry := prometheus.NewRegistry()
	handler := NewHandlerWithRegistry(c, 10*time.Second, logger, registry)

	req := httptest.NewRequest("GET", "/probe", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestProbeHandler_CacheHit(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	c := cache.New(3 * time.Hour)
	defer c.Close()

	// Pre-populate cache
	domain := "example.com"
	expTime := time.Now().Add(365 * 24 * time.Hour)
	entry := &cache.Entry{
		ExpirationTime: expTime,
		Success:        true,
		Error:          "",
		Timestamp:      time.Now(),
		CachedDuration: 3 * time.Hour,
	}
	c.Set(domain, entry)

	registry := prometheus.NewRegistry()
	handler := NewHandlerWithRegistry(c, 10*time.Second, logger, registry)

	req := httptest.NewRequest("GET", fmt.Sprintf("/probe?target=%s", domain), nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "domain_probe_success 1") {
		t.Errorf("expected domain_probe_success 1 in response, got:\n%s", body)
	}

	if !strings.Contains(body, "domain_probe_cached 1") {
		t.Errorf("expected domain_probe_cached 1 in response, got:\n%s", body)
	}
}

func TestProbeHandler_CacheMiss(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	c := cache.New(3 * time.Hour)
	defer c.Close()

	registry := prometheus.NewRegistry()
	handler := NewHandlerWithRegistry(c, 10*time.Second, logger, registry)

	// Request a domain that won't be in cache
	// nolint:godox
	// NOTE: this will actually try to do a WHOIS lookup, which may fail in test env
	req := httptest.NewRequest("GET", "/probe?target=test-nonexistent-domain-xyz.invalid", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	// Should have cache miss indicator
	if !strings.Contains(body, "domain_probe_cached 0") {
		t.Errorf("expected domain_probe_cached 0 in response, got:\n%s", body)
	}
}

func TestProbeHandler_DomainSanitization(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	c := cache.New(3 * time.Hour)
	defer c.Close()

	// Pre-populate cache with lowercase domain
	domain := "example.com"
	expTime := time.Now().Add(365 * 24 * time.Hour)
	entry := &cache.Entry{
		ExpirationTime: expTime,
		Success:        true,
		Error:          "",
	}
	c.Set(domain, entry)

	registry := prometheus.NewRegistry()
	handler := NewHandlerWithRegistry(c, 10*time.Second, logger, registry)

	// Request with uppercase and spaces
	req := httptest.NewRequest("GET", "/probe?target=EXAMPLE.COM", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	// Should find the lowercase version in cache
	if !strings.Contains(body, "domain_probe_cached 1") {
		t.Errorf("expected to find cached entry for uppercase domain request")
	}
}
