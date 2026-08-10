package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxCertificateNames = 32
	maxCapturedError    = 512
	maxConcurrency      = 128
	maxAddresses        = 64
)

// Scanner performs active-but-minimal TLS ALPN handshakes. It never writes application
// bytes to a connection.
type Scanner struct {
	options  Options
	resolver resolver
	rootCAs  *x509.CertPool
}

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type defaultResolver struct{}

func (defaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// New validates options and creates a scanner with certificate verification
// enabled. A custom CA file can extend the system trust roots.
func New(options Options) (*Scanner, error) {
	if options.Concurrency < 0 {
		return nil, fmt.Errorf("concurrency must be positive")
	}
	if options.Concurrency == 0 {
		options.Concurrency = DefaultOptions.Concurrency
	}
	if options.Timeout < 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultOptions.Timeout
	}
	if options.MaxAddresses < 0 {
		return nil, fmt.Errorf("max addresses must be positive")
	}
	if options.MaxAddresses == 0 {
		options.MaxAddresses = DefaultOptions.MaxAddresses
	}
	if options.Concurrency > maxConcurrency {
		return nil, fmt.Errorf("concurrency must not exceed %d", maxConcurrency)
	}
	if options.MaxAddresses > maxAddresses {
		return nil, fmt.Errorf("max addresses must not exceed %d", maxAddresses)
	}
	rootCAs, err := loadRoots(options.CAFile)
	if err != nil {
		return nil, err
	}
	return &Scanner{options: options, resolver: defaultResolver{}, rootCAs: rootCAs}, nil
}

// Options returns the validated options used by the scanner.
func (s *Scanner) Options() Options {
	if s == nil {
		return Options{}
	}
	return s.options
}

// Scan scans targets with bounded worker concurrency and preserves input order.
func (s *Scanner) Scan(ctx context.Context, targets []string) []Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) > MaxTargets {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		return []Result{{
			Target:               "<target-list>",
			ObservedAt:           now,
			Classification:       ClassificationInvalidTarget,
			ClassificationReason: "target list exceeds the scanner safety limit",
			Error:                fmt.Sprintf("target count %d exceeds the limit of %d", len(targets), MaxTargets),
		}}
	}
	targets = deduplicateTargets(targets)
	results := make([]Result, len(targets))
	if len(targets) == 0 {
		return results
	}
	if err := ctx.Err(); err != nil {
		for index := range targets {
			results[index] = canceledResult(targets[index], err)
		}
		return results
	}
	workersCount := s.options.Concurrency
	if workersCount > len(targets) {
		workersCount = len(targets)
	}
	if workersCount < 1 {
		workersCount = 1
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	workers.Add(workersCount)
	for worker := 0; worker < workersCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = s.scanOne(ctx, targets[index])
			}
		}()
	}
	for index := range targets {
		select {
		case jobs <- index:
		case <-ctx.Done():
			results[index] = canceledResult(targets[index], ctx.Err())
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func deduplicateTargets(targets []string) []string {
	unique := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, rawTarget := range targets {
		key := strings.TrimSpace(rawTarget)
		if normalized, err := NormalizeTarget(rawTarget); err == nil {
			key = normalized
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, rawTarget)
	}
	return unique
}

func (s *Scanner) scanOne(parent context.Context, rawTarget string) (result Result) {
	started := time.Now()
	result.Target = strings.TrimSpace(rawTarget)
	result.ObservedAt = started.UTC().Format(time.RFC3339Nano)
	defer func() { result.DurationMillis = time.Since(started).Milliseconds() }()

	target, err := NormalizeTarget(rawTarget)
	if err != nil {
		result.Target = "<invalid-target>"
		result.Classification = ClassificationInvalidTarget
		result.ClassificationReason = "target could not be normalized"
		result.Error = boundedError(err)
		return result
	}
	result.Target = target
	u, err := url.Parse(target)
	if err != nil {
		result.Classification = ClassificationInvalidTarget
		result.ClassificationReason = "target could not be parsed"
		result.Error = boundedError(err)
		return result
	}
	requestContext, cancel := context.WithTimeout(parent, s.options.Timeout)
	defer cancel()
	addresses, resolvedAddressCount, err := s.resolve(requestContext, u)
	if err != nil {
		result.Classification = ClassificationIndeterminate
		result.ClassificationReason = "DNS resolution did not produce a usable address"
		result.Error = boundedError(err)
		return result
	}
	result.ResolvedAddressCount = resolvedAddressCount
	result.OmittedAddressCount = resolvedAddressCount - len(addresses)
	result.AddressLimitReached = result.OmittedAddressCount > 0

	result.Addresses = make([]AddressResult, 0, len(addresses))
	for _, address := range addresses {
		if blockedAddress(address.IP, s.options.AllowPrivate) {
			result.Addresses = append(result.Addresses, AddressResult{
				Address:       address.String(),
				PolicyBlocked: true,
			})
			continue
		}
		addressContext, addressCancel := context.WithTimeout(parent, s.options.Timeout)
		addressResult := s.probeAddress(addressContext, u, address)
		addressCancel()
		result.Addresses = append(result.Addresses, addressResult)
		if addressResult.TLS.NegotiatedProtocol == "h2" {
			result.HTTP2Negotiated = true
		}
	}
	result = finalizeResult(result)
	return result
}

func (s *Scanner) resolve(ctx context.Context, target *url.URL) ([]net.IPAddr, int, error) {
	host := target.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, 1, nil
	}
	addresses, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, 0, fmt.Errorf("resolve %q: no addresses", host)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].String() < addresses[j].String() })
	unique := addresses[:0]
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		key := address.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, address)
	}
	addresses = unique
	resolvedAddressCount := len(addresses)
	if len(addresses) > s.options.MaxAddresses {
		addresses = addresses[:s.options.MaxAddresses]
	}
	return addresses, resolvedAddressCount, nil
}

func (s *Scanner) probeAddress(ctx context.Context, target *url.URL, address net.IPAddr) AddressResult {
	started := time.Now()
	result := AddressResult{Address: address.String()}
	defer func() { result.DurationMillis = time.Since(started).Milliseconds() }()

	port := target.Port()
	if port == "" {
		port = "443"
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
	if err != nil {
		result.Error = boundedError(err)
		return result
	}
	defer connection.Close()

	serverName := target.Hostname()
	config := &tls.Config{
		ServerName: serverName,
		RootCAs:    s.rootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	client := tls.Client(connection, config)
	if err := client.HandshakeContext(ctx); err != nil {
		result.Error = boundedError(err)
		return result
	}
	state := client.ConnectionState()
	result.TLS = tlsInfo(&state)
	result.TLS.Verified = true
	if len(state.PeerCertificates) > 0 {
		result.Certificate = certificateInfo(state.PeerCertificates[0])
	}
	// Deliberately do not call Read or Write after HandshakeContext. TLS
	// handshake bytes are not application protocol bytes.
	return result
}

func finalizeResult(result Result) Result {
	successes := 0
	failures := 0
	blocked := 0
	var firstProtocol AddressResult
	var h2Protocol AddressResult
	gotProtocol := false
	gotH2Protocol := false
	for _, address := range result.Addresses {
		switch {
		case address.PolicyBlocked:
			blocked++
		case address.Error != "":
			failures++
		default:
			successes++
			if address.TLS.NegotiatedProtocol == "h2" && !gotH2Protocol {
				h2Protocol = address
				gotH2Protocol = true
			}
			if !gotProtocol {
				firstProtocol = address
				gotProtocol = true
			}
		}
	}
	result.Complete = successes > 0 && failures == 0 && blocked == 0 && !result.AddressLimitReached
	if result.HTTP2Negotiated {
		result.Protocol = "h2"
		if gotH2Protocol {
			result.TLS = h2Protocol.TLS
		}
	} else if gotProtocol {
		result.Protocol = firstProtocol.TLS.NegotiatedProtocol
		result.TLS = firstProtocol.TLS
	}
	if result.HTTP2Negotiated {
		result.Classification = ClassificationH2Observed
		result.ClassificationReason = "ALPN negotiated h2 on at least one tested address; this does not establish CVE-2023-44487 vulnerability or patch status"
		result.Evidence = []string{"ALPN negotiated h2", "no HTTP request or HTTP/2 stream was sent"}
		if blocked > 0 || failures > 0 || result.AddressLimitReached {
			result.Evidence = append(result.Evidence, "some resolved addresses were not fully observed")
		}
		return result
	}
	if successes == 0 && blocked > 0 && failures == 0 && !result.AddressLimitReached {
		result.Classification = ClassificationNotScannedPolicy
		result.ClassificationReason = "all resolved addresses were blocked by the address policy"
		result.Evidence = []string{"use --allow-private only when scanning a deliberately controlled private target"}
		return result
	}
	if successes == 0 || failures > 0 || blocked > 0 || result.AddressLimitReached {
		result.Classification = ClassificationIndeterminate
		result.ClassificationReason = "the tested addresses did not provide a complete successful ALPN observation"
		if result.AddressLimitReached {
			result.Evidence = []string{"address limit reached; not all resolved addresses were tested"}
		}
		return result
	}
	result.Classification = ClassificationH2NotObserved
	result.ClassificationReason = "all tested addresses completed TLS without negotiating h2; this is limited to the tested network path"
	result.Evidence = []string{"ALPN did not negotiate h2", "no HTTP request or HTTP/2 stream was sent"}
	return result
}

func canceledResult(target string, err error) Result {
	return Result{
		Target:               "<unscanned-target>",
		ObservedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		Classification:       ClassificationIndeterminate,
		ClassificationReason: "scan canceled before this target was checked",
		Error:                boundedError(err),
	}
}

func tlsInfo(state *tls.ConnectionState) TLSInfo {
	return TLSInfo{
		Version:            tlsVersionName(state.Version),
		CipherSuite:        tls.CipherSuiteName(state.CipherSuite),
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func certificateInfo(certificate *x509.Certificate) CertificateInfo {
	fingerprint := sha256.Sum256(certificate.Raw)
	info := CertificateInfo{
		Subject:   certificate.Subject.String(),
		Issuer:    certificate.Issuer.String(),
		NotBefore: certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  certificate.NotAfter.UTC().Format(time.RFC3339),
		SHA256:    hex.EncodeToString(fingerprint[:]),
	}
	if len(certificate.DNSNames) > maxCertificateNames {
		info.DNSNames = append([]string(nil), certificate.DNSNames[:maxCertificateNames]...)
	} else {
		info.DNSNames = append([]string(nil), certificate.DNSNames...)
	}
	return info
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate pool: %w", err)
		}
		return roots, nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", path, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("CA file %q contains no certificates", path)
	}
	return roots, nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > maxCapturedError {
		return message[:maxCapturedError] + "..."
	}
	return message
}

// blockedAddress rejects non-unicast and private/reserved addresses by
// default. --allow-private is an explicit opt-in for controlled local tests.
func blockedAddress(ip net.IP, allowPrivate bool) bool {
	if ip == nil || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if allowPrivate {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return reservedAddress(ip)
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3ffe::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func reservedAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
