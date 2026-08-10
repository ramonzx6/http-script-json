// Package scanner provides an active-but-minimal TLS ALPN probe for HTTP/2 exposure.
//
// A probe performs a TLS handshake only. It does not send an HTTP request,
// HTTP/2 preface, stream, reset, flood, or any other application bytes. Seeing
// h2 in ALPN establishes protocol exposure on the tested path, not whether the
// implementation is vulnerable to CVE-2023-44487.
package scanner

import "time"

// MaxTargets bounds allocations and network work from positional or JSON input.
const MaxTargets = 4096

// Classification is intentionally conservative. The scanner cannot establish
// a server's patch status from a handshake, so h2 always requires review.
type Classification string

const (
	ClassificationH2Observed       Classification = "h2_observed_review_required"
	ClassificationH2NotObserved    Classification = "h2_not_observed_on_tested_path"
	ClassificationIndeterminate    Classification = "indeterminate"
	ClassificationNotScannedPolicy Classification = "not_scanned_policy"
	ClassificationInvalidTarget    Classification = "invalid_target"
)

// Options controls resource, transport, and safety limits.
type Options struct {
	Concurrency  int
	Timeout      time.Duration
	MaxAddresses int
	AllowPrivate bool
	CAFile       string
}

var DefaultOptions = Options{
	Concurrency:  4,
	Timeout:      10 * time.Second,
	MaxAddresses: 8,
}

// TLSInfo contains non-secret TLS handshake details.
type TLSInfo struct {
	Verified           bool   `json:"verified"`
	Version            string `json:"version,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	NegotiatedProtocol string `json:"negotiated_protocol,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
}

// CertificateInfo contains bounded certificate identity and validity details.
type CertificateInfo struct {
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	DNSNames  []string `json:"dns_names,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
}

// AddressResult records one resolved address attempt.
type AddressResult struct {
	Address          string          `json:"address"`
	PolicyBlocked    bool            `json:"policy_blocked"`
	TLS              TLSInfo         `json:"tls"`
	Certificate      CertificateInfo `json:"certificate"`
	DurationMillis   int64           `json:"duration_ms"`
	ApplicationBytes bool            `json:"application_bytes_sent"`
	Error            string          `json:"error,omitempty"`
}

// Result is one target's active-but-minimal observation. HTTP response fields are absent
// by design: an ALPN-only probe never sends an HTTP request or receives one.
type Result struct {
	Target               string          `json:"target"`
	ObservedAt           string          `json:"observed_at"`
	Complete             bool            `json:"complete"`
	Protocol             string          `json:"protocol,omitempty"`
	HTTP2Negotiated      bool            `json:"http2_negotiated"`
	DurationMillis       int64           `json:"duration_ms"`
	TLS                  TLSInfo         `json:"tls"`
	Addresses            []AddressResult `json:"addresses,omitempty"`
	ResolvedAddressCount int             `json:"resolved_address_count"`
	OmittedAddressCount  int             `json:"omitted_address_count"`
	AddressLimitReached  bool            `json:"address_limit_reached"`
	Evidence             []string        `json:"evidence,omitempty"`
	Classification       Classification  `json:"classification"`
	ClassificationReason string          `json:"classification_reason"`
	Error                string          `json:"error,omitempty"`
}

type Summary struct {
	Total            int `json:"total"`
	Complete         int `json:"complete"`
	Incomplete       int `json:"incomplete"`
	H2ObservedReview int `json:"h2_observed_review_required"`
	H2NotObserved    int `json:"h2_not_observed_on_tested_path"`
	Indeterminate    int `json:"indeterminate"`
	NotScannedPolicy int `json:"not_scanned_policy"`
	InvalidTarget    int `json:"invalid_target"`
}

type Report struct {
	SchemaVersion int      `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Results       []Result `json:"results"`
	Summary       Summary  `json:"summary"`
}

// NewReport adds stable schema metadata and computes the aggregate summary.
func NewReport(results []Result) Report {
	return Report{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Results:       results,
		Summary:       Summarize(results),
	}
}

func Summarize(results []Result) Summary {
	summary := Summary{Total: len(results)}
	for _, result := range results {
		if result.Complete {
			summary.Complete++
		} else {
			summary.Incomplete++
		}
		switch result.Classification {
		case ClassificationH2Observed:
			summary.H2ObservedReview++
		case ClassificationH2NotObserved:
			summary.H2NotObserved++
		case ClassificationIndeterminate:
			summary.Indeterminate++
		case ClassificationNotScannedPolicy:
			summary.NotScannedPolicy++
		case ClassificationInvalidTarget:
			summary.InvalidTarget++
		}
	}
	return summary
}
