// Package whois provides WHOIS lookup and domain expiration date parsing.
package whois

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"go.uber.org/zap"
)

// ExpirationResult holds the result of a WHOIS lookup.
type ExpirationResult struct {
	ExpirationTime time.Time
	Success        bool
	Error          string
}

var (
	errInvalidDomain               = errors.New("invalid domain format")
	errExpireFieldNotFound         = errors.New("expire field not found")
	errValidUntilFieldNotFound     = errors.New("valid until field not found")
	errExpiresFieldNotFound        = errors.New("expires field not found")
	errRenewalExpirationNotFound   = errors.New("renewal/expiration date field not found")
	errExpireDateFieldNotFound     = errors.New("expire date field not found")
	errRegistrarExpirationNotFound = errors.New("registrar registration expiration date field not found")
	errExpirationDateNotFound      = errors.New("expiration date field not found")
	errRegistryExpiryDateNotFound  = errors.New("registry expiry date field not found")
	errNoFallbackParser            = errors.New("no fallback parser for TLD")
	errNoFieldsParsed              = errors.New("none of the fields found or parsed")
	errCouldNotParseDate           = errors.New("could not parse date")
)

// Lookup performs a WHOIS query for a domain and returns the expiration date.
func Lookup(domain string, whoisServer string, timeout time.Duration, logger *zap.Logger) ExpirationResult {
	result := ExpirationResult{
		Success: false,
	}

	// Extract TLD from domain
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		result.Error = errInvalidDomain.Error()
		return result
	}
	tld := parts[len(parts)-1]

	// Perform WHOIS query
	var resp string
	var err error

	client := whois.NewClient()
	client.SetTimeout(timeout)

	if whoisServer != "" {
		// Use custom WHOIS server
		resp, err = client.Whois(domain, whoisServer)
	} else {
		// Auto-detect WHOIS server
		resp, err = client.Whois(domain)
	}

	if err != nil {
		result.Error = fmt.Sprintf("whois query failed: %v", err)
		logger.Debug("WHOIS query failed", zap.String("domain", domain), zap.Error(err))
		return result
	}

	// Try to parse with the standard parser first
	parsed, err := whoisparser.Parse(resp)
	if err == nil && parsed.Domain != nil && parsed.Domain.ExpirationDate != "" {
		t, err := parseExpirationDate(parsed.Domain.ExpirationDate)
		if err == nil {
			result.ExpirationTime = t
			result.Success = true
			return result
		}
	}

	// Fall back to TLD-specific parsing
	expiryTime, err := fallbackParse(resp, tld)
	if err == nil {
		result.ExpirationTime = expiryTime
		result.Success = true
		return result
	}

	result.Error = fmt.Sprintf("failed to extract expiration date for TLD %s: %v", tld, err)
	logger.Debug("Failed to extract expiration date", zap.String("domain", domain), zap.String("tld", tld))

	return result
}

// fallbackParse handles TLDs that the standard parser doesn't cover well.
// nolint:gocyclo
func fallbackParse(whoisResp string, tld string) (time.Time, error) {
	resp := strings.ToLower(whoisResp)

	switch tld {
	case "ua", "pp.ua", "biz.ua", "co.ua", "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua":
		// .ua domains use "Expiration Date:" or "paid-till:"
		return parseLineField(resp, []string{"expiration date:", "paid-till:"}, dateFormats)

	case "cz":
		// .cz uses "expire:" with dd.mm.yyyy format
		date := extractField(resp, "expire:")
		if date == "" {
			return time.Time{}, errExpireFieldNotFound
		}
		return parseDate(date, []string{"02.01.2006"})

	case "sk":
		// .sk uses "Valid Until:" format
		date := extractField(resp, "valid until:")
		if date == "" {
			return time.Time{}, errValidUntilFieldNotFound
		}
		return parseDate(date, dateFormats)

	case "se", "nu":
		// .se and .nu use "expires:" format
		date := extractField(resp, "expires:")
		if date == "" {
			return time.Time{}, errExpiresFieldNotFound
		}
		return parseDate(date, dateFormats)

	case "pl":
		// .pl uses "renewal date:" or "expiration date:" format
		date := extractField(resp, "renewal date:")
		if date == "" {
			date = extractField(resp, "expiration date:")
		}
		if date == "" {
			return time.Time{}, errRenewalExpirationNotFound
		}
		return parseDate(date, dateFormats)

	case "it":
		// .it uses "Expire Date:" format
		date := extractField(resp, "expire date:")
		if date == "" {
			return time.Time{}, errExpireDateFieldNotFound
		}
		return parseDate(date, dateFormats)

	case "br":
		// .br uses "expires:" format
		date := extractField(resp, "expires:")
		if date == "" {
			return time.Time{}, errExpiresFieldNotFound
		}
		return parseDate(date, dateFormats)

	case "do":
		// .do uses "Registrar Registration Expiration Date:" format
		date := extractField(resp, "registrar registration expiration date:")
		if date == "" {
			return time.Time{}, errRegistrarExpirationNotFound
		}
		return parseDate(date, dateFormats)

	case "id":
		// .id uses "Expiration Date:" format
		date := extractField(resp, "expiration date:")
		if date == "" {
			return time.Time{}, errExpirationDateNotFound
		}
		return parseDate(date, dateFormats)

	case "mx":
		// .mx uses "Expiration Date:" format
		date := extractField(resp, "expiration date:")
		if date == "" {
			return time.Time{}, errExpirationDateNotFound
		}
		return parseDate(date, dateFormats)

	case "fm":
		// .fm uses "Registry Expiry Date:" format
		date := extractField(resp, "registry expiry date:")
		if date == "" {
			return time.Time{}, errRegistryExpiryDateNotFound
		}
		return parseDate(date, dateFormats)

	default:
		return time.Time{}, fmt.Errorf("%w %s", errNoFallbackParser, tld)
	}
}

var dateFormats = []string{
	"2006-01-02",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"02.01.2006",
	"01-02-2006",
	"01/02/2006",
}

// extractField extracts the value of a field from WHOIS response.
func extractField(resp, field string) string {
	lines := strings.Split(resp, "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, field) {
			// Extract everything after the field name
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// parseLineField tries to find and parse a date from one of several possible field names.
func parseLineField(resp string, fields []string, formats []string) (time.Time, error) {
	for _, field := range fields {
		date := extractField(resp, field)
		if date != "" {
			t, err := parseDate(date, formats)
			if err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, errNoFieldsParsed
}

// parseDate attempts to parse a date string using multiple formats.
func parseDate(dateStr string, formats []string) (time.Time, error) {
	// Clean up the date string
	dateStr = strings.TrimSpace(dateStr)

	// Extract just the date part (up to 'T' if present)
	if idx := strings.IndexByte(dateStr, 'T'); idx != -1 {
		dateStr = dateStr[:idx]
	}

	for _, format := range formats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("%w '%s' with any known format", errCouldNotParseDate, dateStr)
}

// parseExpirationDate parses the expiration date returned by the whois-parser library.
func parseExpirationDate(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)

	// Extract just the date part (up to 'T' if present)
	if idx := strings.IndexByte(dateStr, 'T'); idx != -1 {
		dateStr = dateStr[:idx]
	}

	for _, format := range dateFormats {
		t, err := time.Parse(format, dateStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("%w '%s'", errCouldNotParseDate, dateStr)
}
