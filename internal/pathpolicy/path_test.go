package pathpolicy

import (
	"net/url"
	"strings"
	"testing"
)

func TestParsePreservesRawPathAndNormalizesOnlyEscapeCaseForMatching(t *testing.T) {
	cases := []struct {
		raw, match string
	}{
		{"/", "/"},
		{"/api/projects/group%2fproject", "/api/projects/group%2Fproject"},
		{"/packages/@types%2Fnode", "/packages/@types%2Fnode"},
		{"/files/report%2etxt", "/files/report%2Etxt"},
		{"/safe//admin", "/safe//admin"},
		{"/safe/%5Cadmin", "/safe/%5Cadmin"},
	}
	for _, c := range cases {
		got, err := Parse(c.raw)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", c.raw, err)
			continue
		}
		if got.Raw != c.raw || got.Match != c.match {
			t.Errorf("%q: got Raw=%q Match=%q", c.raw, got.Raw, got.Match)
		}
	}
}

func TestParseRejectsParentTraversalAfterCommonDecodeLayers(t *testing.T) {
	for _, raw := range []string{
		"/safe/../admin",
		"/safe/%2e%2e/admin",
		"/safe%2F..%2Fadmin",
		`/safe\..\admin`,
		"/safe/%252E%252E/admin",
		"/safe%252F..%252Fadmin",
		"/safe/%25252E%25252E/admin",
		"/safe/%25%32%45%25%32%45/admin",
		"/safe/..;/admin",
		"/safe/%2E%2E;param/admin",
		"/safe/..%3Bparam/admin",
		"/safe/%2E%2E%3Bparam/admin",
		"/safe/%00admin",
	} {
		if got, err := Parse(raw); err == nil {
			t.Errorf("%q: got %+v, want an error", raw, got)
		}
	}
}

func TestParseBoundsPathLengthAndNestedEncodingWork(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", maxPathBytes)
	if _, err := Parse(tooLong); err == nil {
		t.Fatal("expected an overlong path error")
	}
	tooNested := "/safe/%" + strings.Repeat("25", maxDecodeRounds+2) + "2E"
	if _, err := Parse(tooNested); err == nil {
		t.Fatal("expected excessive nested encoding to fail")
	}
}

func TestParseRejectsMalformedRequestPaths(t *testing.T) {
	for _, raw := range []string{
		"",
		"relative/path",
		"/api/%zz",
		"/api/%",
		"/api?query",
		"/api#fragment",
		`/api\admin`,
		"/api/x|y",
		"/api/café",
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%q: expected an error", raw)
		}
	}
}

func TestFromURLPreservesClientSpellingForForwarding(t *testing.T) {
	u, err := url.ParseRequestURI("/api/projects/group%2fproject/files/caf%C3%A9%7Cnotes?next=%2Fadmin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromURL(u, "/api/projects/group%2fproject/files/caf%C3%A9%7Cnotes?next=%2Fadmin")
	if err != nil {
		t.Fatal(err)
	}
	got.Apply(u)
	if got.Match != "/api/projects/group%2Fproject/files/caf%C3%A9%7Cnotes" {
		t.Fatalf("match path = %q", got.Match)
	}
	if forwarded := u.RequestURI(); forwarded != "/api/projects/group%2fproject/files/caf%C3%A9%7Cnotes?next=%2Fadmin" {
		t.Fatalf("forwarded request URI = %q", forwarded)
	}
}

func TestFromURLRejectsDecodedPathDisagreement(t *testing.T) {
	u := &url.URL{Path: "/allowed"}
	if _, err := FromURL(u, "/other"); err == nil {
		t.Fatal("expected mismatched escaped and decoded paths to fail")
	}
}
