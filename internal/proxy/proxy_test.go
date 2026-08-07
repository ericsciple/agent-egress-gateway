package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericsciple/agent-egress-gateway/internal/ca"
	"github.com/ericsciple/agent-egress-gateway/internal/config"
)

const lanesJSON = `[
  {"name":"sentry","placeholder":"PLACEHOLDER_SENTRY_XYZ","real":"REAL-SENTRY-SECRET",
   "targets":[{"host":"sentry.io","path_prefix":"/api/0/projects/acme/"}]},
  {"name":"gitlab","placeholder":"PLACEHOLDER_GITLAB_XYZ","real":"REAL-GITLAB-SECRET","header":"Private-Token",
   "targets":[{"host":"gitlab.com"}]}
]`

// capture records what the proxy did upstream, so tests can assert on the host
// actually dialled rather than the host the client claimed.
type capture struct {
	mu           sync.Mutex
	dialedHosts  []string
	lastRequest  *http.Request
	lastRawBytes string
}

func (c *capture) dialed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.dialedHosts...)
}

// newHarness returns a proxy whose upstream is an in-memory pipe, plus a client
// TLS config that trusts the generated CA.
func newHarness(t *testing.T, egressAllow string) (*Proxy, *tls.Config, *capture) {
	t.Helper()

	cfg, err := config.Load(lanesJSON, egressAllow)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	authority, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	cap := &capture{}
	p := New(cfg, authority)
	p.Log = func(string) {}

	// A real loopback listener stands in for the upstream. net.Pipe is unbuffered
	// and synchronous, which deadlocks when both ends try to write a TLS
	// close_notify at the same time.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for fake upstream: %v", err)
	}
	t.Cleanup(func() { upstreamLn.Close() })

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				cap.mu.Lock()
				cap.lastRequest = req
				var sb strings.Builder
				req.Header.Write(&sb)
				cap.lastRawBytes = sb.String()
				cap.mu.Unlock()

				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(conn)
		}
	}()

	p.Dial = func(host string) (net.Conn, error) {
		cap.mu.Lock()
		cap.dialedHosts = append(cap.dialedHosts, host)
		cap.mu.Unlock()
		return net.Dial("tcp", upstreamLn.Addr().String())
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("could not trust the generated CA")
	}
	return p, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, cap
}

// roundTrip drives one request through the proxy. sni is the TLS server name the
// client presents; hostHeader overrides the Host header when non-empty.
func roundTrip(t *testing.T, p *Proxy, clientTLS *tls.Config, sni, hostHeader, path string, headers map[string]string) *http.Response {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for proxy: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.Serve(conn, "203.0.113.10:443")
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling proxy: %v", err)
	}

	cc := clientTLS.Clone()
	cc.ServerName = sni
	tlsClient := tls.Client(raw, cc)
	defer tlsClient.Close()

	_ = tlsClient.SetDeadline(time.Now().Add(10 * time.Second))

	host := sni
	if hostHeader != "" {
		host = hostHeader
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host)
	for k, v := range headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("Connection: close\r\n\r\n")

	if _, err := io.WriteString(tlsClient, sb.String()); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	// Drain so the capture goroutine has certainly recorded the request.
	io.Copy(io.Discard, resp.Body)
	return resp
}

func TestSwapHappensOnMatchingLane(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := cap.lastRequest.Header.Get("Authorization")
	if got != "Bearer REAL-SENTRY-SECRET" {
		t.Errorf("upstream Authorization = %q, want the real credential with the Bearer prefix preserved", got)
	}
	if strings.Contains(got, "PLACEHOLDER_SENTRY_XYZ") {
		t.Error("placeholder still present upstream")
	}
}

// The prefix the caller sent must survive, which is why the swap is a substring
// replacement rather than rebuilding the header from a template.
func TestSwapPreservesCallerFormat(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "gitlab.com", "", "/api/v4/projects",
		map[string]string{"Private-Token": "PLACEHOLDER_GITLAB_XYZ"})
	defer resp.Body.Close()

	if got := cap.lastRequest.Header.Get("Private-Token"); got != "REAL-GITLAB-SECRET" {
		t.Errorf("Private-Token = %q, want the bare credential with no added prefix", got)
	}
}

// A placeholder outside the lane's declared header is forwarded untouched. We do
// not scan for it, and we do not refuse the request: it is a worthless string.
func TestPlaceholderElsewhereIsNotSwapped(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/acme/issues",
		map[string]string{
			"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ",
			"X-Sneaky":      "PLACEHOLDER_SENTRY_XYZ",
		})
	defer resp.Body.Close()

	if got := cap.lastRequest.Header.Get("X-Sneaky"); got != "PLACEHOLDER_SENTRY_XYZ" {
		t.Errorf("X-Sneaky = %q, want the placeholder passed through unchanged", got)
	}
	if strings.Contains(cap.lastRawBytes, "REAL-SENTRY-SECRET") &&
		strings.Count(cap.lastRawBytes, "REAL-SENTRY-SECRET") != 1 {
		t.Error("the real credential appeared more than once; the swap escaped its header")
	}
}

// A lane's placeholder presented on a different lane's host is not swapped,
// because lane selection is by destination and the wrong lane's header is not
// touched.
func TestCrossLanePlaceholderIsNotSwapped(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "gitlab.com", "", "/api/v4/projects",
		map[string]string{"Private-Token": "PLACEHOLDER_SENTRY_XYZ"})
	defer resp.Body.Close()

	if got := cap.lastRequest.Header.Get("Private-Token"); got != "PLACEHOLDER_SENTRY_XYZ" {
		t.Errorf("Private-Token = %q, want sentry's placeholder left alone on gitlab's lane", got)
	}
	if strings.Contains(cap.lastRawBytes, "REAL-SENTRY-SECRET") {
		t.Error("sentry's credential leaked onto gitlab's lane")
	}
}

func TestPathOutsidePrefixIsBlocked(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/someone-else/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if len(cap.dialed()) != 0 {
		t.Errorf("blocked request still dialled upstream: %v", cap.dialed())
	}
}

// THE security test. A caller presents SNI for a host it controls, so the TLS
// name is legitimate, but claims a lane target in the Host header. The lane must
// not match, and above all the real credential must not be sent anywhere.
func TestHostHeaderCannotDivergeFromTLSName(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "attacker.example")
	resp := roundTrip(t, p, clientTLS, "attacker.example", "sentry.io", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a Host header disagreeing with the TLS name", resp.StatusCode)
	}
	if strings.Contains(cap.lastRawBytes, "REAL-SENTRY-SECRET") {
		t.Fatal("CREDENTIAL LEAK: the real credential was sent after a Host/SNI mismatch")
	}
	for _, h := range cap.dialed() {
		if h != "attacker.example" {
			t.Errorf("dialled %q, which is not the TLS name the connection arrived under", h)
		}
	}
}

// The upstream host is always the host the lane matched on, never the original
// destination the connection was redirected from. In the sandbox the redirect
// happens inside the guest, so that address is guest-controlled.
func TestUpstreamIsTheMatchedHostNotTheOriginalDestination(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})
	defer resp.Body.Close()

	dialed := cap.dialed()
	if len(dialed) != 1 || dialed[0] != "sentry.io" {
		t.Errorf("dialled %v, want exactly [sentry.io] regardless of the 203.0.113.10 original destination", dialed)
	}
}

func TestEgressAllowForwardsWithNoCredential(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "cdn.example")
	resp := roundTrip(t, p, clientTLS, "cdn.example", "", "/assets/app.js", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(cap.lastRawBytes, "REAL-") {
		t.Error("a credential was attached to an egress-allow host")
	}
}

func TestUnknownHostIsBlocked(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "unknown.example", "", "/", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if len(cap.dialed()) != 0 {
		t.Errorf("blocked request still dialled upstream: %v", cap.dialed())
	}
}

// Reaching an authorised destination without carrying the placeholder gets no
// credential. The caller has to ask, every time.
func TestNoPlaceholderMeansNoCredential(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/acme/issues", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(cap.lastRawBytes, "REAL-SENTRY-SECRET") {
		t.Error("a credential was attached to a request that did not ask for one")
	}
}
