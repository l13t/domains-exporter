package whois

import (
	"testing"
	"time"
)

// TestFallbackParse tests the fallback parser with known WHOIS responses.
func TestFallbackParse(t *testing.T) {
	tests := []struct {
		name       string
		tld        string
		whoisResp  string
		wantErr    bool
		checkYear  int
		checkMonth time.Month
		checkDay   int
	}{
		{
			name: ".ua domain with Expiration Date",
			tld:  "ua",
			whoisResp: `
domain:        example.ua
expiration date: 2025-12-31
status:        OK
`,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name: ".cz domain with expire date",
			tld:  "cz",
			whoisResp: `
domain:        example.cz
expire: 31.12.2025
status:        OK
`,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name: ".se domain with expires",
			tld:  "se",
			whoisResp: `
domain:        example.se
expires: 2026-01-15
status:        active
`,
			wantErr:    false,
			checkYear:  2026,
			checkMonth: time.January,
			checkDay:   15,
		},
		{
			name: ".ua domain with paid-till",
			tld:  "ua",
			whoisResp: `
domain:        example.ua
paid-till: 2025-06-30
status:        OK
`,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.June,
			checkDay:   30,
		},
		{
			name: ".sk domain with Valid Until",
			tld:  "sk",
			whoisResp: `
domain:        example.sk
Valid Until: 2024-08-20
status:        OK
`,
			wantErr:    false,
			checkYear:  2024,
			checkMonth: time.August,
			checkDay:   20,
		},
		{
			name: "unknown TLD should error",
			tld:  "xyz",
			whoisResp: `
domain: example.xyz
expiry: 2025-01-01
`,
			wantErr: true,
		},
		{
			name: ".ua domain missing date field",
			tld:  "ua",
			whoisResp: `
domain:        example.ua
status:        OK
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fallbackParse(tt.whoisResp, tt.tld)
			if (err != nil) != tt.wantErr {
				t.Errorf("fallbackParse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Year() != tt.checkYear || got.Month() != tt.checkMonth || got.Day() != tt.checkDay {
					t.Errorf("fallbackParse() got date = %v-%v-%v, want %v-%v-%v",
						got.Year(), got.Month(), got.Day(),
						tt.checkYear, tt.checkMonth, tt.checkDay)
				}
			}
		})
	}
}

// TestExtractField tests the field extraction logic.
func TestExtractField(t *testing.T) {
	tests := []struct {
		name    string
		resp    string
		field   string
		want    string
		wantErr bool
	}{
		{
			name: "simple field extraction",
			resp: `domain: example.com
expiration date: 2025-12-31
status: active`,
			field:   "expiration date:",
			want:    "2025-12-31",
			wantErr: false,
		},
		{
			name: "field with extra spaces",
			resp: `Domain:     example.com
Registry Expiry Date:    2025-12-31T00:00:00Z
Status:     clientTransferProhibited`,
			field:   "registry expiry date:",
			want:    "2025-12-31T00:00:00Z",
			wantErr: false,
		},
		{
			name: "field not found",
			resp: `domain: example.com
status: active`,
			field:   "expiration date:",
			want:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractField(tt.resp, tt.field)
			if got != tt.want {
				t.Errorf("extractField() got = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseDate tests date parsing with multiple formats.
func TestParseDate(t *testing.T) {
	tests := []struct {
		name       string
		dateStr    string
		formats    []string
		wantErr    bool
		checkYear  int
		checkMonth time.Month
		checkDay   int
	}{
		{
			name:       "ISO format",
			dateStr:    "2025-12-31",
			formats:    dateFormats,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name:       "ISO with time (should trim)",
			dateStr:    "2025-12-31T23:59:59Z",
			formats:    dateFormats,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name:       "DD.MM.YYYY format",
			dateStr:    "31.12.2025",
			formats:    dateFormats,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name:    "invalid format",
			dateStr: "invalid-date",
			formats: dateFormats,
			wantErr: true,
		},
		{
			name:       "date with surrounding spaces",
			dateStr:    "  2025-12-31  ",
			formats:    dateFormats,
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDate(tt.dateStr, tt.formats)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Year() != tt.checkYear || got.Month() != tt.checkMonth || got.Day() != tt.checkDay {
					t.Errorf("parseDate() got date = %v-%v-%v, want %v-%v-%v",
						got.Year(), got.Month(), got.Day(),
						tt.checkYear, tt.checkMonth, tt.checkDay)
				}
			}
		})
	}
}

// TestParseExpirationDate tests parsing expiration dates from whois-parser output.
func TestParseExpirationDate(t *testing.T) {
	tests := []struct {
		name       string
		dateStr    string
		wantErr    bool
		checkYear  int
		checkMonth time.Month
		checkDay   int
	}{
		{
			name:       "standard ISO format",
			dateStr:    "2025-12-31",
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.December,
			checkDay:   31,
		},
		{
			name:       "ISO with time",
			dateStr:    "2025-06-15T00:00:00Z",
			wantErr:    false,
			checkYear:  2025,
			checkMonth: time.June,
			checkDay:   15,
		},
		{
			name:    "unparseable date",
			dateStr: "not-a-date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExpirationDate(tt.dateStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExpirationDate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Year() != tt.checkYear || got.Month() != tt.checkMonth || got.Day() != tt.checkDay {
					t.Errorf("parseExpirationDate() got date = %v-%v-%v, want %v-%v-%v",
						got.Year(), got.Month(), got.Day(),
						tt.checkYear, tt.checkMonth, tt.checkDay)
				}
			}
		})
	}
}
