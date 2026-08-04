package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestValidateTargetProductionAndDevelopmentPolicies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		policy TargetPolicy
		valid  bool
	}{
		{name: "production HTTPS", target: "https://hooks.example.test/a2a", valid: true},
		{name: "query rejected", target: "https://hooks.example.test/a2a?subscription=1", valid: false},
		{name: "production HTTP", target: "http://hooks.example.test/a2a"},
		{name: "development HTTP", target: "http://localhost:8080/a2a", policy: TargetPolicy{AllowHTTP: true, AllowPrivateNetworks: true}, valid: true},
		{name: "userinfo", target: "https://user:secret@hooks.example.test/a2a"},
		{name: "fragment", target: "https://hooks.example.test/a2a#secret"},
		{name: "private literal", target: "https://10.0.0.1/a2a"},
		{name: "documentation literal", target: "https://192.0.2.1/a2a"},
		{name: "private development literal", target: "https://10.0.0.1/a2a", policy: TargetPolicy{AllowPrivateNetworks: true}, valid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateTarget(test.target, test.policy)
			if (err == nil) != test.valid {
				t.Fatalf("ValidateTarget(%q) error = %v, valid = %t", test.target, err, test.valid)
			}
		})
	}
}

func TestPublicWebhookAddressRejectsPrivateAndSpecialUseRanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		public  bool
	}{
		{address: "8.8.8.8", public: true},
		{address: "2606:4700:4700::1111", public: true},
		{address: "0.0.0.1"},
		{address: "10.0.0.1"},
		{address: "100.64.0.1"},
		{address: "127.0.0.1"},
		{address: "169.254.169.254"},
		{address: "192.0.2.1"},
		{address: "198.18.0.1"},
		{address: "240.0.0.1"},
		{address: "::1"},
		{address: "fc00::1"},
		{address: "fe80::1"},
		{address: "2001:db8::1"},
		{address: "2002:c0a8:101::1"},
		{address: "3fff::1"},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := publicWebhookAddress(netip.MustParseAddr(test.address)); got != test.public {
				t.Fatalf("publicWebhookAddress(%q) = %t, want %t", test.address, got, test.public)
			}
		})
	}
}

func TestGuardedDialerResolvesThenDialsOnlyApprovedLiteral(t *testing.T) {
	t.Parallel()
	resolver := staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("8.8.8.8"),
	}}
	dialer := &recordingDialer{err: errors.New("stop")}
	guard := guardedDialer{resolver: resolver, dialer: dialer}
	if _, err := guard.DialContext(context.Background(), "tcp", "webhook.example:443"); err == nil {
		t.Fatal("DialContext() error = nil")
	}
	if len(dialer.addresses) != 1 || dialer.addresses[0] != "8.8.8.8:443" {
		t.Fatalf("dialed addresses = %v, want only the public literal", dialer.addresses)
	}
}

func TestGuardedDialerFailsClosedWhenDNSReturnsOnlyPrivateAddresses(t *testing.T) {
	t.Parallel()
	dialer := &recordingDialer{}
	guard := guardedDialer{
		resolver: staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1")}},
		dialer:   dialer,
	}
	if _, err := guard.DialContext(context.Background(), "tcp", "rebound.example:443"); err == nil || !strings.Contains(err.Error(), "private or special-use") {
		t.Fatalf("DialContext() error = %v", err)
	}
	if len(dialer.addresses) != 0 {
		t.Fatalf("private addresses reached dialer: %v", dialer.addresses)
	}
}

func TestNewHTTPClientDisablesProxyRedirectsAndOldTLS(t *testing.T) {
	t.Parallel()
	client, err := NewHTTPClient(HTTPClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("webhook transport retained proxy support")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("webhook transport does not require TLS 1.2+")
	}
	if transport.DialTLS != nil || transport.DialTLSContext != nil {
		t.Fatal("TLS-specific dial hook can bypass guarded DialContext")
	}

	finalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/start" {
			http.Redirect(response, request, "/final", http.StatusFound)
			return
		}
		finalRequests++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	developmentClient, err := NewHTTPClient(HTTPClientConfig{Policy: TargetPolicy{AllowHTTP: true, AllowPrivateNetworks: true}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := developmentClient.Do(request); !errors.Is(err, errRedirectsDisabled) {
		t.Fatalf("redirect error = %v, want errRedirectsDisabled", err)
	}
	if finalRequests != 0 {
		t.Fatalf("redirect target requests = %d, want 0", finalRequests)
	}
}

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), r.err
}

type recordingDialer struct {
	addresses []string
	err       error
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return nil, d.err
}
