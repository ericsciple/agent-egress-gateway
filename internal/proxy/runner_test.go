package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ericsciple/agent-egress-gateway/internal/ca"
	"github.com/ericsciple/agent-egress-gateway/internal/config"
)

// recordingTransport captures what the runner actually sent upstream, including
// the host it dialled, without touching the network.
type recordingTransport struct {
	dialedHosts []string
	lastHeader  http.Header
	lastURI     string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.dialedHosts = append(rt.dialedHosts, r.URL.Host)
	rt.lastHeader = r.Header.Clone()
	rt.lastURI = r.URL.RequestURI()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    r,
	}, nil
}

func newRunner(t *testing.T, egressAllow string) (http.Handler, *recordingTransport) {
	return newRunnerWithLanes(t, lanesJSON, egressAllow)
}

func newRunnerWithLanes(t *testing.T, lanes, egressAllow string) (http.Handler, *recordingTransport) {
	t.Helper()
	cfg, err := config.Load(lanes, egressAllow)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	authority, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	rt := &recordingTransport{}
	p := New(cfg, authority)
	p.Log = func(string) {}
	p.Transport = rt
	return p.RunnerHandler(), rt
}

func doRunner(h http.Handler, host, path string, headers map[string]string) *httptest.ResponseRecorder {
	return doRunnerMethod(h, "GET", host, path, headers)
}

func doRunnerMethod(h http.Handler, method, host, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if host != "" {
		req.Header.Set(HostHeader, host)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRunnerSwapsOnMatchingLane(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "sentry.io", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rt.lastHeader.Get("Authorization"); got != "Bearer REAL-SENTRY-SECRET" {
		t.Errorf("Authorization = %q, want the real credential with the prefix preserved", got)
	}
}

// The host we dial comes from the same value we matched on, so the two cannot
// diverge even though the guest supplies it.
func TestRunnerDialsTheMatchedHost(t *testing.T) {
	h, rt := newRunner(t, "")
	doRunner(h, "sentry.io", "/api/0/projects/acme/issues",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})

	if len(rt.dialedHosts) != 1 || rt.dialedHosts[0] != "sentry.io" {
		t.Errorf("dialled %v, want [sentry.io]", rt.dialedHosts)
	}
}

func TestRunnerRejectsMissingHostHeader(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "", "/api/0/projects/acme/issues", nil)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when %s is absent", rec.Code, HostHeader)
	}
	if len(rt.dialedHosts) != 0 {
		t.Errorf("dialled %v despite a missing host header", rt.dialedHosts)
	}
}

func TestRunnerBlocksUnknownHost(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "unknown.example", "/whatever", nil)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if len(rt.dialedHosts) != 0 {
		t.Errorf("blocked request still dialled: %v", rt.dialedHosts)
	}
}

func TestRunnerBlocksPathOutsidePrefix(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "sentry.io", "/api/0/projects/someone-else/x",
		map[string]string{"Authorization": "Bearer PLACEHOLDER_SENTRY_XYZ"})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if len(rt.dialedHosts) != 0 {
		t.Errorf("blocked request still dialled: %v", rt.dialedHosts)
	}
}

func TestRunnerEscapedPathIsMatchedAndForwardedWithoutRewriting(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "sentry.io", "/api/0/projects/acme/group%2fproject/caf%C3%A9%7Cnotes?next=%2Fadmin",
		map[string]string{"Authorization": "******"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rt.lastURI != "/api/0/projects/acme/group%2fproject/caf%C3%A9%7Cnotes?next=%2Fadmin" {
		t.Fatalf("upstream request URI = %q", rt.lastURI)
	}
	if got := rt.lastHeader.Get("Authorization"); got != "******" {
		t.Fatalf("upstream Authorization = %q", got)
	}
}

func TestRunnerEscapedPathPrefixMatchesHexCaseWithoutDecoding(t *testing.T) {
	lanes := `[{"name":"gitlab","placeholder":"PH","real":"REAL",
	           "targets":[{"host":"gitlab.com","path_prefix":"/api/v4/projects/group%2fproject/"}]}]`
	h, rt := newRunnerWithLanes(t, lanes, "")
	rec := doRunner(h, "gitlab.com", "/api/v4/projects/group%2Fproject/issues",
		map[string]string{"Authorization": "PH"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rt.lastHeader.Get("Authorization"); got != "REAL" {
		t.Fatalf("upstream Authorization = %q", got)
	}
	if rt.lastURI != "/api/v4/projects/group%2Fproject/issues" {
		t.Fatalf("upstream request URI = %q", rt.lastURI)
	}
}

func TestRunnerEscapedSeparatorCannotSatisfyLiteralPathPrefix(t *testing.T) {
	h, rt := newRunner(t, "")
	rec := doRunner(h, "sentry.io", "/api/0/projects%2Facme/issues",
		map[string]string{"Authorization": "******"})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if len(rt.dialedHosts) != 0 {
		t.Fatalf("escaped separator request dialled upstream: %v", rt.dialedHosts)
	}
}

func TestRunnerRejectsTraversalPathsBeforeSwapOrDial(t *testing.T) {
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
			h, rt := newRunner(t, "")
			rec := doRunner(h, "sentry.io", requestPath,
				map[string]string{"Authorization": "******"})

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if len(rt.dialedHosts) != 0 {
				t.Fatalf("ambiguous request dialled upstream: %v", rt.dialedHosts)
			}
			if rt.lastHeader != nil {
				t.Fatal("ambiguous request reached the upstream transport")
			}
		})
	}
}

func TestRunnerAllowsEncodedIdentifiersDotsAndRepeatedSeparators(t *testing.T) {
	for _, requestPath := range []string{
		"/api/0/projects/acme/group%2Fproject",
		"/api/0/projects/acme/report%2Etxt",
		"/api/0/projects/acme//admin",
		"/api/0/projects/acme/./admin",
		"/api/0/projects/acme/caf%C3%A9%7Cnotes",
	} {
		t.Run(requestPath, func(t *testing.T) {
			h, rt := newRunner(t, "")
			rec := doRunner(h, "sentry.io", requestPath,
				map[string]string{"Authorization": "******"})

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if rt.lastURI != requestPath {
				t.Fatalf("upstream request URI = %q, want %q", rt.lastURI, requestPath)
			}
		})
	}
}

// The tunnel's auth headers are for the relay. Forwarding them would hand the
// tunnel token to whichever upstream we dial.
func TestRunnerStripsTunnelHeaders(t *testing.T) {
	h, rt := newRunner(t, "")
	doRunner(h, "sentry.io", "/api/0/projects/acme/issues", map[string]string{
		"Authorization":                    "Bearer PLACEHOLDER_SENTRY_XYZ",
		"X-Tunnel-Authorization":           "tunnel SECRET-TUNNEL-TOKEN",
		"X-Tunnel-Skip-Anti-Phishing-Page": "true",
	})

	if got := rt.lastHeader.Get("X-Tunnel-Authorization"); got != "" {
		t.Errorf("tunnel token forwarded upstream: %q", got)
	}
	if got := rt.lastHeader.Get(HostHeader); got != "" {
		t.Errorf("%s forwarded upstream: %q", HostHeader, got)
	}
	if rt.lastHeader.Get("Authorization") == "" {
		t.Error("Authorization was stripped, but it is the header the swap targets")
	}
}

func TestRunnerCrossLanePlaceholderIsNotSwapped(t *testing.T) {
	h, rt := newRunner(t, "")
	doRunner(h, "gitlab.com", "/api/v4/projects",
		map[string]string{"Private-Token": "PLACEHOLDER_SENTRY_XYZ"})

	if got := rt.lastHeader.Get("Private-Token"); got != "PLACEHOLDER_SENTRY_XYZ" {
		t.Errorf("Private-Token = %q, want sentry's placeholder left untouched on gitlab's lane", got)
	}
	for _, vs := range rt.lastHeader {
		for _, s := range vs {
			if strings.Contains(s, "REAL-SENTRY-SECRET") {
				t.Fatal("sentry's credential leaked onto gitlab's lane")
			}
		}
	}
}

func TestRunnerEgressAllowGetsNoCredential(t *testing.T) {
	h, rt := newRunner(t, "cdn.example")
	rec := doRunner(h, "cdn.example", "/assets/app.js", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, vs := range rt.lastHeader {
		for _, s := range vs {
			if strings.Contains(s, "REAL-") {
				t.Error("a credential was attached to an egress-allow host")
			}
		}
	}
}

// The capability that "replace, not inject" exists to provide: two credentials on
// one endpoint, chosen by the placeholder the caller carries. Selecting on
// destination alone would make the second unreachable.
func TestTwoCredentialsOnOneEndpoint(t *testing.T) {
	twoLanes := `[
	  {"name":"read","placeholder":"PH_READ_XYZ","real":"REAL-READ-TOKEN","targets":[{"host":"api.example","path_prefix":"/v1/"}]},
	  {"name":"write","placeholder":"PH_WRITE_XYZ","real":"REAL-WRITE-TOKEN","targets":[{"host":"api.example","path_prefix":"/v1/"}]}
	]`
	cfg, err := config.Load(twoLanes, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	authority, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	for _, c := range []struct{ placeholder, want string }{
		{"PH_READ_XYZ", "REAL-READ-TOKEN"},
		{"PH_WRITE_XYZ", "REAL-WRITE-TOKEN"},
	} {
		rt := &recordingTransport{}
		p := New(cfg, authority)
		p.Log = func(string) {}
		p.Transport = rt

		doRunner(p.RunnerHandler(), "api.example", "/v1/things",
			map[string]string{"Authorization": "Bearer " + c.placeholder})

		got := rt.lastHeader.Get("Authorization")
		if got != "Bearer "+c.want {
			t.Errorf("carrying %s produced %q, want %q", c.placeholder, got, "Bearer "+c.want)
		}
	}
}

// Reaching an authorised endpoint without carrying any placeholder still attaches
// nothing, even when several credentials are permitted there.
func TestNoPlaceholderAmongSeveralLanesAttachesNothing(t *testing.T) {
	twoLanes := `[
	  {"name":"read","placeholder":"PH_READ_XYZ","real":"REAL-READ-TOKEN","targets":[{"host":"api.example","path_prefix":"/v1/"}]},
	  {"name":"write","placeholder":"PH_WRITE_XYZ","real":"REAL-WRITE-TOKEN","targets":[{"host":"api.example","path_prefix":"/v1/"}]}
	]`
	cfg, _ := config.Load(twoLanes, "")
	authority, _ := ca.New()
	rt := &recordingTransport{}
	p := New(cfg, authority)
	p.Log = func(string) {}
	p.Transport = rt

	rec := doRunner(p.RunnerHandler(), "api.example", "/v1/things", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, vs := range rt.lastHeader {
		for _, s := range vs {
			if strings.Contains(s, "REAL-") {
				t.Error("a credential was attached to a request that asked for none")
			}
		}
	}
}

// A credential scoped to reads must not be attached to a write, even on the very
// path it covers. The token itself can write; the gateway is what stops it.
func TestRunnerMethodScoping(t *testing.T) {
	readOnly := `[{"name":"GH_TOKEN","placeholder":"PH_GH","real":"REAL-GH-TOKEN","targets":[
	               {"host":"api.github.com","path_prefix":"/repos/acme/widgets","methods":["GET","HEAD"]}]}]`
	cfg, err := config.Load(readOnly, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	authority, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}

	run := func(method string) (*httptest.ResponseRecorder, *recordingTransport) {
		rt := &recordingTransport{}
		p := New(cfg, authority)
		p.Log = func(string) {}
		p.Transport = rt
		rec := doRunnerMethod(p.RunnerHandler(), method, "api.github.com", "/repos/acme/widgets/issues",
			map[string]string{"Authorization": "Bearer PH_GH"})
		return rec, rt
	}

	rec, rt := run("GET")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	if got := rt.lastHeader.Get("Authorization"); got != "Bearer REAL-GH-TOKEN" {
		t.Errorf("GET Authorization = %q, want the real credential", got)
	}

	rec, rt = run("DELETE")
	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE status = %d, want 403", rec.Code)
	}
	if len(rt.dialedHosts) != 0 {
		t.Errorf("DELETE still dialled upstream: %v", rt.dialedHosts)
	}
	if rt.lastHeader != nil {
		for _, vs := range rt.lastHeader {
			for _, v := range vs {
				if strings.Contains(v, "REAL-GH-TOKEN") {
					t.Fatal("CREDENTIAL LEAK: the credential was attached to a method outside its scope")
				}
			}
		}
	}
}
