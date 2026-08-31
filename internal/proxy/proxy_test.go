package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

func (c *capture) requestURI() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastRequest == nil {
		return ""
	}
	return c.lastRequest.RequestURI
}

// newHarness returns a proxy whose upstream is an in-memory pipe, plus a client
// TLS config that trusts the generated CA.
func newHarness(t *testing.T, egressAllow string) (*Proxy, *tls.Config, *capture) {
	return newHarnessWithLanes(t, lanesJSON, egressAllow)
}

func newHarnessWithLanes(t *testing.T, lanes, egressAllow string) (*Proxy, *tls.Config, *capture) {
	t.Helper()

	cfg, err := config.Load(lanes, egressAllow)
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

func TestEscapedPathIsMatchedAndForwardedWithoutRewriting(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "",
		"/api/0/projects/acme/group%2fproject/caf%C3%A9%7Cnotes?next=%2Fadmin",
		map[string]string{"Authorization": "******"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := cap.requestURI(); got != "/api/0/projects/acme/group%2fproject/caf%C3%A9%7Cnotes?next=%2Fadmin" {
		t.Fatalf("upstream request URI = %q", got)
	}
	if got := cap.lastRequest.Header.Get("Authorization"); got != "******" {
		t.Fatalf("upstream Authorization = %q", got)
	}
}

func TestEscapedPathPrefixMatchesHexCaseWithoutDecoding(t *testing.T) {
	lanes := `[{"name":"gitlab","placeholder":"PH","real":"REAL",
	           "targets":[{"host":"gitlab.com","path_prefix":"/api/v4/projects/group%2fproject/"}]}]`
	p, clientTLS, cap := newHarnessWithLanes(t, lanes, "")
	resp := roundTrip(t, p, clientTLS, "gitlab.com", "",
		"/api/v4/projects/group%2Fproject/issues",
		map[string]string{"Authorization": "PH"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := cap.lastRequest.Header.Get("Authorization"); got != "REAL" {
		t.Fatalf("upstream Authorization = %q", got)
	}
	if got := cap.requestURI(); got != "/api/v4/projects/group%2Fproject/issues" {
		t.Fatalf("upstream request URI = %q", got)
	}
}

func TestEscapedSeparatorCannotSatisfyLiteralPathPrefix(t *testing.T) {
	p, clientTLS, cap := newHarness(t, "")
	resp := roundTrip(t, p, clientTLS, "sentry.io", "",
		"/api/0/projects%2Facme/issues",
		map[string]string{"Authorization": "******"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := cap.dialed(); len(got) != 0 {
		t.Fatalf("escaped separator request dialled upstream: %v", got)
	}
}

func TestInterceptRejectsTraversalPathsBeforeSwapOrDial(t *testing.T) {
	for _, requestPath := range []string{
		"/api/0/projects/acme/%2e%2e/admin",
		"/api/0/projects/acme%2f..%2fadmin",
		`/api/0/projects/acme\..\admin`,
		"/api/0/projects/acme/%252e%252e/admin",
		"/api/0/projects/acme/%25252e%25252e/admin",
		"/api/0/projects/acme/%25%32%45%25%32%45/admin",
		"/api/0/projects/acme/..;param/admin",
		"/api/0/projects/acme/..%3bparam/admin",
	} {
		t.Run(requestPath, func(t *testing.T) {
			p, clientTLS, cap := newHarness(t, "")
			resp := roundTrip(t, p, clientTLS, "sentry.io", "", requestPath,
				map[string]string{"Authorization": "******"})
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if got := cap.dialed(); len(got) != 0 {
				t.Fatalf("ambiguous request dialled upstream: %v", got)
			}
			if strings.Contains(cap.lastRawBytes, "REAL-SENTRY-SECRET") {
				t.Fatal("credential was substituted before path rejection")
			}
		})
	}
}

func TestInterceptAllowsEncodedIdentifiersDotsAndRepeatedSeparators(t *testing.T) {
	for _, requestPath := range []string{
		"/api/0/projects/acme/group%2Fproject",
		"/api/0/projects/acme/report%2Etxt",
		"/api/0/projects/acme//admin",
		"/api/0/projects/acme/./admin",
		"/api/0/projects/acme/caf%C3%A9%7Cnotes",
	} {
		t.Run(requestPath, func(t *testing.T) {
			p, clientTLS, cap := newHarness(t, "")
			resp := roundTrip(t, p, clientTLS, "sentry.io", "", requestPath,
				map[string]string{"Authorization": "******"})
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := cap.requestURI(); got != requestPath {
				t.Fatalf("upstream request URI = %q, want %q", got, requestPath)
			}
		})
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

func TestBasicCredentialIsDecodedSwappedAndReEncoded(t *testing.T) {
	// The end-to-end shape of `curl -u user:$TOKEN`: the placeholder is inside
	// base64, so nothing about it is visible in the header value itself. What
	// matters is what the UPSTREAM receives.
	p, clientTLS, cap := newHarness(t, "")
	creds := base64.StdEncoding.EncodeToString([]byte("user:PLACEHOLDER_SENTRY_XYZ"))
	resp := roundTrip(t, p, clientTLS, "sentry.io", "", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Basic " + creds})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := cap.lastRequest.Header.Get("Authorization")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "Basic "))
	if err != nil {
		t.Fatalf("upstream Authorization was not valid Basic: %q", got)
	}
	if string(raw) != "user:REAL-SENTRY-SECRET" {
		t.Errorf("upstream credential = %q, want the real secret in the password field", raw)
	}
	if strings.Contains(got, "PLACEHOLDER_SENTRY_XYZ") {
		t.Error("placeholder still present upstream")
	}
}

func TestBasicCredentialOutsideItsLaneIsNotSwapped(t *testing.T) {
	// Base64 must not become a way around lane scoping: the same credential on a
	// host the lane does not cover still gets nothing.
	p, clientTLS, cap := newHarness(t, "registry.npmjs.org")
	creds := base64.StdEncoding.EncodeToString([]byte("user:PLACEHOLDER_SENTRY_XYZ"))
	resp := roundTrip(t, p, clientTLS, "registry.npmjs.org", "", "/left-pad",
		map[string]string{"Authorization": "Basic " + creds})
	defer resp.Body.Close()

	got := cap.lastRequest.Header.Get("Authorization")
	if strings.Contains(got, "REAL-SENTRY-SECRET") {
		t.Fatal("the real credential was attached on a host outside the lane")
	}
	if got != "Basic "+creds {
		t.Errorf("value was rewritten to %q; it should pass through untouched", got)
	}
}
