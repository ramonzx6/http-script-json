package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare host", "Example.COM", "https://example.com/"},
		{"bare host port", "Example.COM:8443", "https://example.com:8443/"},
		{"explicit HTTPS", "HTTPS://Example.COM:8443", "https://example.com:8443/"},
		{"trailing dot", "https://Example.COM./", "https://example.com/"},
		{"default port", "Example.COM:443", "https://example.com/"},
		{"ipv6", "https://[::1]:443", "https://[::1]/"},
		{"scoped ipv6", "https://[fe80::1%25Eth0]", "https://[fe80::1%25Eth0]/"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeTarget(test.in)
			if err != nil {
				t.Fatalf("NormalizeTarget() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("NormalizeTarget() = %q, want %q", got, test.want)
			}
		})
	}
	for _, input := range []string{"", "https://", "ftp://example.com", "http://example.com", "https://user:pass@example.com", "example.com:", "https://[::1]:", "https://example.com:0", "https://[fe80::1%25]", "https://[fe80::1%25Eth0%2525bad]", "https://example.com/path", "https://example.com?query", "example.com bad"} {
		if _, err := NormalizeTarget(input); err == nil {
			t.Errorf("NormalizeTarget(%q) unexpectedly succeeded", input)
		}
	}
}

func TestScopedIPv6ResolutionPreservesZoneAndStripsItFromTLSName(t *testing.T) {
	probe, err := New(Options{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("https://[fe80::1%25Eth0]/")
	if err != nil {
		t.Fatal(err)
	}
	addresses, count, err := probe.resolve(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(addresses) != 1 {
		t.Fatalf("resolve() returned %d addresses (count %d), want one", len(addresses), count)
	}
	if addresses[0].Zone != "Eth0" {
		t.Fatalf("resolved zone = %q, want %q", addresses[0].Zone, "Eth0")
	}
	if got := addresses[0].String(); got != "fe80::1%Eth0" {
		t.Fatalf("resolved address = %q, want %q", got, "fe80::1%Eth0")
	}
	if got, _, _ := splitIPv6Zone(target.Hostname()); got != "fe80::1" {
		t.Fatalf("TLS server name host = %q, want %q", got, "fe80::1")
	}
}

func TestDecodeTargets(t *testing.T) {
	for _, input := range []string{
		`["example.com", "https://example.org"]`,
		`{"urls":["example.com"]}`,
		`{"targets":["example.com"]}`,
	} {
		targets, err := DecodeTargets(strings.NewReader(input))
		if err != nil || len(targets) == 0 {
			t.Fatalf("DecodeTargets(%s) = %#v, %v", input, targets, err)
		}
	}
	if _, err := DecodeTargets(strings.NewReader(`[] []`)); err == nil {
		t.Fatal("DecodeTargets accepted multiple top-level values")
	}
	tooMany := make([]string, MaxTargets+1)
	encoded, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTargets(strings.NewReader(string(encoded))); err == nil {
		t.Fatal("DecodeTargets accepted too many targets")
	}
}

func TestScanALPNOnlyNegotiatesH2WithoutApplicationBytes(t *testing.T) {
	address, applicationBytes, der := tlsProbeServer(t, []string{"h2", "http/1.1"})
	probe, err := New(Options{AllowPrivate: true, CAFile: writeCAFile(t, der), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"https://" + address})[0]
	if result.Classification != ClassificationH2Observed {
		t.Fatalf("classification = %q, want %q (error %s)", result.Classification, ClassificationH2Observed, result.Error)
	}
	if !result.HTTP2Negotiated || result.Protocol != "h2" {
		t.Fatalf("result did not record h2: %#v", result)
	}
	if !result.Complete || !result.TLS.Verified || !result.Addresses[0].TLS.Verified || result.Addresses[0].Certificate.SHA256 == "" || result.ObservedAt == "" {
		t.Fatalf("result is missing verified TLS evidence: %#v", result)
	}
	if result.Addresses[0].ApplicationBytes {
		t.Fatal("scanner reported application bytes")
	}
	select {
	case n := <-applicationBytes:
		if n > 0 {
			t.Fatalf("scanner sent %d application bytes after handshake", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS probe server did not finish")
	}
}

func TestScanWithoutH2IsLimitedToTestedPath(t *testing.T) {
	address, _, der := tlsProbeServer(t, []string{"http/1.1"})
	probe, err := New(Options{AllowPrivate: true, CAFile: writeCAFile(t, der), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"https://" + address})[0]
	if result.Classification != ClassificationH2NotObserved {
		t.Fatalf("classification = %q, want %q (error %s)", result.Classification, ClassificationH2NotObserved, result.Error)
	}
	if !result.Complete {
		t.Fatalf("successful non-h2 result was marked incomplete: %#v", result)
	}
	if result.HTTP2Negotiated || result.Protocol != "http/1.1" {
		t.Fatalf("unexpected protocol result: %#v", result)
	}
}

func TestPrivateAddressPolicy(t *testing.T) {
	address, _, _ := tlsProbeServer(t, []string{"h2"})
	probe, err := New(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"https://" + address})[0]
	if result.Classification != ClassificationNotScannedPolicy {
		t.Fatalf("classification = %q, want %q", result.Classification, ClassificationNotScannedPolicy)
	}
	if len(result.Addresses) != 1 || !result.Addresses[0].PolicyBlocked {
		t.Fatalf("policy-blocked result was not recorded: %#v", result.Addresses)
	}
}

func TestCertificateVerificationDefault(t *testing.T) {
	address, _, _ := tlsProbeServer(t, []string{"h2"})
	probe, err := New(Options{AllowPrivate: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"https://" + address})[0]
	if result.Classification != ClassificationIndeterminate {
		t.Fatalf("classification = %q, want %q", result.Classification, ClassificationIndeterminate)
	}
	if len(result.Addresses) != 1 || result.Addresses[0].Error == "" {
		t.Fatalf("expected certificate verification error: %#v", result)
	}
}

func TestTLSHandshakeUsesPerAddressTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
	})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		<-release
	}()

	probe, err := New(Options{AllowPrivate: true, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result := probe.Scan(context.Background(), []string{"https://" + listener.Addr().String()})[0]
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("TLS timeout took %s", elapsed)
	}
	if result.Classification != ClassificationIndeterminate || result.Complete || len(result.Addresses) != 1 || result.Addresses[0].Error == "" {
		t.Fatalf("timeout result = %#v", result)
	}
}

func TestInvalidNonHTTPS(t *testing.T) {
	probe, err := New(DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"http://example.com"})[0]
	if result.Classification != ClassificationInvalidTarget {
		t.Fatalf("classification = %q, want %q", result.Classification, ClassificationInvalidTarget)
	}
}

func TestSummaryJSON(t *testing.T) {
	results := []Result{{Classification: ClassificationH2Observed}, {Classification: ClassificationInvalidTarget}}
	data, err := json.Marshal(NewReport(results))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"h2_observed_review_required":1`) {
		t.Fatalf("summary JSON missing h2 count: %s", data)
	}
	if !strings.Contains(string(data), `"schema_version":1`) {
		t.Fatalf("report JSON missing schema version: %s", data)
	}
	if !strings.Contains(string(data), `"incomplete":2`) {
		t.Fatalf("summary JSON missing completeness count: %s", data)
	}
}

func TestInvalidTargetDoesNotEchoCredentials(t *testing.T) {
	probe, err := New(DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	result := probe.Scan(context.Background(), []string{"https://secret@example.com"})[0]
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("invalid target leaked credentials: %s", encoded)
	}
}

func TestBlockedAddress(t *testing.T) {
	for _, ip := range []string{
		"0.0.0.1", "127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "224.0.0.1",
		"64:ff9b::1", "2001:db8::1", "2002::1", "3fff::1", "ff02::1",
	} {
		if !blockedAddress(net.ParseIP(ip), false) {
			t.Errorf("blockedAddress(%s) = false", ip)
		}
	}
	if blockedAddress(net.ParseIP("127.0.0.1"), true) {
		t.Error("allowPrivate blocked loopback")
	}
	if blockedAddress(net.ParseIP("169.254.1.1"), true) {
		t.Error("allowPrivate blocked link-local address")
	}
}

func TestPartialH2ObservationIsIncomplete(t *testing.T) {
	result := finalizeResult(Result{
		HTTP2Negotiated: true,
		Addresses: []AddressResult{
			{Address: "203.0.113.1", TLS: TLSInfo{Verified: true, NegotiatedProtocol: "h2"}},
			{Address: "203.0.113.2", Error: "connect failed"},
		},
	})
	if result.Classification != ClassificationH2Observed || result.Complete {
		t.Fatalf("partial h2 result = %#v", result)
	}
	if result.Protocol != "h2" || !result.TLS.Verified {
		t.Fatalf("top-level h2 evidence is inconsistent: %#v", result)
	}
}

func TestTruncatedH2ObservationIsIncomplete(t *testing.T) {
	result := finalizeResult(Result{
		HTTP2Negotiated:     true,
		AddressLimitReached: true,
		Addresses: []AddressResult{
			{Address: "203.0.113.1", TLS: TLSInfo{Verified: true, NegotiatedProtocol: "h2"}},
		},
	})
	if result.Classification != ClassificationH2Observed || result.Complete {
		t.Fatalf("truncated h2 result = %#v", result)
	}
}

func TestAddressLimitMakesBlockedResultIndeterminate(t *testing.T) {
	probe, err := New(Options{MaxAddresses: 1})
	if err != nil {
		t.Fatal(err)
	}
	probe.resolver = staticResolver{
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("203.0.113.1")},
	}
	result := probe.Scan(context.Background(), []string{"limit.example"})[0]
	if result.Classification != ClassificationIndeterminate {
		t.Fatalf("classification = %q, want %q", result.Classification, ClassificationIndeterminate)
	}
	if !result.AddressLimitReached || result.ResolvedAddressCount != 2 || result.OmittedAddressCount != 1 {
		t.Fatalf("address truncation was not recorded: %#v", result)
	}
}

func TestResolveDeduplicatesBeforeApplyingLimit(t *testing.T) {
	probe, err := New(Options{MaxAddresses: 1})
	if err != nil {
		t.Fatal(err)
	}
	probe.resolver = staticResolver{
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("192.0.2.1")},
	}
	target, err := NormalizeTarget("duplicates.example")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	addresses, total, err := probe.resolve(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(addresses) != 1 {
		t.Fatalf("resolve() returned total=%d addresses=%#v", total, addresses)
	}
}

func TestNewRejectsNegativeAndExcessiveLimits(t *testing.T) {
	for _, options := range []Options{
		{Concurrency: -1},
		{Timeout: -time.Second},
		{MaxAddresses: -1},
		{Concurrency: maxConcurrency + 1},
		{MaxAddresses: maxAddresses + 1},
	} {
		if _, err := New(options); err == nil {
			t.Errorf("New(%#v) unexpectedly succeeded", options)
		}
	}
}

func TestCanceledScan(t *testing.T) {
	probe, err := New(DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := probe.Scan(ctx, []string{"https://secret@example.com"})[0]
	if result.Classification != ClassificationIndeterminate {
		t.Fatalf("unexpected canceled result: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") {
		t.Fatalf("canceled result leaked credentials: %s", encoded)
	}
}

func TestScanDeduplicatesNormalizedTargets(t *testing.T) {
	probe, err := New(DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	results := probe.Scan(context.Background(), []string{"127.0.0.1", "https://127.0.0.1/", "127.0.0.1:443"})
	if len(results) != 1 {
		t.Fatalf("Scan() returned %d duplicate results: %#v", len(results), results)
	}
}

func TestScanRejectsExcessiveTargetCountBeforeAllocation(t *testing.T) {
	probe, err := New(DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	results := probe.Scan(context.Background(), make([]string, MaxTargets+1))
	if len(results) != 1 || results[0].Classification != ClassificationInvalidTarget {
		t.Fatalf("Scan() excessive-target result = %#v", results)
	}
}

type staticResolver []net.IPAddr

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r...), nil
}

func tlsProbeServer(t *testing.T, protocols []string) (string, <-chan int, []byte) {
	t.Helper()
	seed := httptest.NewTLSServer(nil)
	certificate := seed.TLS.Certificates[0]
	seed.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: protocols})
	finished := make(chan int, 1)
	t.Cleanup(func() { tlsListener.Close() })
	go func() {
		connection, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			finished <- 0
			return
		}
		defer connection.Close()
		if tlsConnection, ok := connection.(*tls.Conn); ok {
			_ = tlsConnection.Handshake()
		}
		_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, 1)
		n, _ := connection.Read(buffer)
		finished <- n
	}()
	return listener.Addr().String(), finished, certificate.Certificate[0]
}

func writeCAFile(t *testing.T, der []byte) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}
