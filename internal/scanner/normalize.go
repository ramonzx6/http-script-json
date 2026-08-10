package scanner

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// NormalizeTarget accepts an HTTPS URL or hostname. Bare hostnames use HTTPS.
// ALPN is an authority-level property, so paths, queries, and fragments are
// rejected instead of being silently ignored.
func NormalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("target is empty")
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("target contains whitespace or control characters")
		}
	}
	candidate := raw
	if !hasScheme(candidate) {
		candidate = "https://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid target syntax")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("target must include a hostname")
	}
	if u.User != nil || strings.ContainsAny(u.Host, "@\r\n\t ") {
		return "", fmt.Errorf("target must not include credentials or invalid host characters")
	}
	hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if hostname == "" {
		return "", fmt.Errorf("target has an empty hostname")
	}
	port := u.Port()
	if port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("target contains an invalid port")
		}
	}
	if strings.Contains(hostname, ":") {
		if net.ParseIP(hostname) == nil {
			return "", fmt.Errorf("target contains an invalid IPv6 hostname")
		}
		if port != "" && port != "443" {
			u.Host = net.JoinHostPort(hostname, port)
		} else {
			u.Host = "[" + hostname + "]"
		}
	} else if port != "" && port != "443" {
		u.Host = net.JoinHostPort(hostname, port)
	} else {
		u.Host = hostname
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", fmt.Errorf("target must be an HTTPS authority without path, query, or fragment")
	}
	u.Path = "/"
	return u.String(), nil
}

func hasScheme(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return false
	}
	scheme := strings.ToLower(value[:colon])
	return scheme == "http" || scheme == "https"
}
