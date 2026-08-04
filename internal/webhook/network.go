package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Resolver is the subset of net.Resolver needed by the SSRF-safe dialer.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Dialer is the subset of net.Dialer needed after an address has passed the
// network policy.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// TargetPolicy controls explicitly insecure development exceptions. The zero
// value is the production policy: HTTPS and publicly routable addresses only.
type TargetPolicy struct {
	AllowHTTP            bool
	AllowPrivateNetworks bool
}

// HTTPClientConfig configures the production webhook transport. Resolver and
// Dialer are injectable to make the resolution-to-dial binding testable.
type HTTPClientConfig struct {
	Policy   TargetPolicy
	Timeout  time.Duration
	Resolver Resolver
	Dialer   Dialer
}

// ValidateTarget validates the URL-level webhook policy. DNS results are
// deliberately validated later in DialContext to prevent DNS rebinding.
func ValidateTarget(raw string, policy TargetPolicy) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Host == "" || target.Opaque != "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("webhook target must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	switch strings.ToLower(target.Scheme) {
	case "https":
		target.Scheme = "https"
	case "http":
		if !policy.AllowHTTP {
			return nil, fmt.Errorf("webhook target must use HTTPS")
		}
		target.Scheme = "http"
	default:
		return nil, fmt.Errorf("webhook target must use HTTPS")
	}
	if target.Hostname() == "" {
		return nil, fmt.Errorf("webhook target host is required")
	}
	if literal, err := netip.ParseAddr(target.Hostname()); err == nil && !policy.AllowPrivateNetworks && !publicWebhookAddress(literal) {
		return nil, fmt.Errorf("webhook target uses a private or special-use address")
	}
	return target, nil
}

// NewHTTPClient returns a transport that follows no redirects, ignores proxy
// environment variables, requires TLS 1.2+, and connects only to addresses
// validated after resolution. It never passes the original hostname to the
// dialer, closing the DNS-rebinding check/use gap.
func NewHTTPClient(cfg HTTPClientConfig) (*http.Client, error) {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	guard := guardedDialer{resolver: resolver, dialer: dialer, allowPrivate: cfg.Policy.AllowPrivateNetworks}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           guard.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectsDisabled
		},
	}, nil
}

type guardedDialer struct {
	resolver     Resolver
	dialer       Dialer
	allowPrivate bool
}

func (d guardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse webhook destination: %w", err)
	}
	addresses, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve webhook destination: %w", err)
	}
	var lastErr error
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if !d.allowPrivate && !publicWebhookAddress(candidate) {
			continue
		}
		connection, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("connect to webhook destination: %w", lastErr)
	}
	return nil, fmt.Errorf("webhook destination resolved only to private or special-use addresses")
}

var blockedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	globalIPv6Prefix    = netip.MustParsePrefix("2000::/3")
	blockedIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

func publicWebhookAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() {
		return false
	}
	if address.Is4() {
		for _, prefix := range blockedIPv4Prefixes {
			if prefix.Contains(address) {
				return false
			}
		}
		return true
	}
	if !globalIPv6Prefix.Contains(address) {
		return false
	}
	for _, prefix := range blockedIPv6Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
