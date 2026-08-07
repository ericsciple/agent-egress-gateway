package config

import "testing"

const twoLanes = `[
  {"name":"sentry","placeholder":"PH_SENTRY","real":"real-sentry",
   "targets":[{"host":"sentry.io","path_prefix":"/api/0/projects/acme/"}]},
  {"name":"gitlab","placeholder":"PH_GITLAB","real":"real-gitlab","header":"Private-Token",
   "targets":[{"host":"gitlab.com"}]}
]`

func TestLoadParsesLanes(t *testing.T) {
	cfg, err := Load(twoLanes, "example.com, cdn.example.com")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Lanes) != 2 {
		t.Fatalf("got %d lanes, want 2", len(cfg.Lanes))
	}
	if got := cfg.Lanes[0].HeaderName(); got != "authorization" {
		t.Errorf("default header = %q, want authorization", got)
	}
	if got := cfg.Lanes[1].HeaderName(); got != "private-token" {
		t.Errorf("explicit header = %q, want private-token", got)
	}
	if !cfg.AllowsEgress("EXAMPLE.COM") {
		t.Error("egress allow should be case-insensitive")
	}
}

func TestMatchRespectsPathPrefix(t *testing.T) {
	cfg, err := Load(twoLanes, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		host, path string
		wantLane   string
	}{
		{"sentry.io", "/api/0/projects/acme/checkout/", "sentry"},
		{"SENTRY.IO", "/api/0/projects/acme/", "sentry"},
		{"sentry.io", "/api/0/projects/other/", ""},
		{"sentry.io", "/", ""},
		{"gitlab.com", "/anything/at/all", "gitlab"},
		{"unknown.example", "/api/0/projects/acme/", ""},
	}
	for _, c := range cases {
		lanes := cfg.LanesFor("GET", c.host, c.path)
		got := ""
		if len(lanes) > 0 {
			got = lanes[0].Name
		}
		if got != c.wantLane {
			t.Errorf("LaneFor(%q, %q) = %q, want %q", c.host, c.path, got, c.wantLane)
		}
	}
}

func TestLoadRejectsBadConfig(t *testing.T) {
	cases := []struct{ name, json string }{
		{"malformed", `{`},
		{"no name", `[{"placeholder":"P","real":"R","targets":[{"host":"h.example"}]}]`},
		{"no placeholder", `[{"name":"a","real":"R","targets":[{"host":"h.example"}]}]`},
		{"no real", `[{"name":"a","placeholder":"P","targets":[{"host":"h.example"}]}]`},
		{"no targets", `[{"name":"a","placeholder":"P","real":"R","targets":[]}]`},
		{"empty host", `[{"name":"a","placeholder":"P","real":"R","targets":[{"host":"  "}]}]`},
		{"relative prefix", `[{"name":"a","placeholder":"P","real":"R","targets":[{"host":"h.example","path_prefix":"api/"}]}]`},
		{"duplicate name", `[{"name":"a","placeholder":"P1","real":"R","targets":[{"host":"h.example"}]},
		                     {"name":"a","placeholder":"P2","real":"R","targets":[{"host":"i.example"}]}]`},
		{"duplicate placeholder", `[{"name":"a","placeholder":"P","real":"R","targets":[{"host":"h.example"}]},
		                            {"name":"b","placeholder":"P","real":"R","targets":[{"host":"i.example"}]}]`},
		{"reserved host", `[{"name":"a","placeholder":"P","real":"R","targets":[{"host":"api.githubcopilot.com"}]}]`},
	}
	for _, c := range cases {
		if _, err := Load(c.json, ""); err == nil {
			t.Errorf("%s: expected an error, got none", c.name)
		}
	}
}

// api.github.com is deliberately usable: pointing a user-supplied token at the
// REST API is a supported scenario, not something to block.
func TestGitHubAPIIsNotReserved(t *testing.T) {
	j := `[{"name":"gh","placeholder":"P","real":"R","targets":[{"host":"api.github.com","path_prefix":"/repos/acme/"}]}]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("api.github.com should be allowed as a lane target: %v", err)
	}
	if len(cfg.LanesFor("GET", "api.github.com", "/repos/acme/thing")) == 0 {
		t.Error("expected the api.github.com lane to match")
	}
}

// The action's own inference lane must be able to name a host user lanes cannot.
func TestInternalLaneMayUseReservedHost(t *testing.T) {
	j := `[{"name":"copilot-inference","internal":true,"placeholder":"P","real":"R",
	       "targets":[{"host":"api.githubcopilot.com"}]}]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("an internal lane should be allowed to use a reserved host: %v", err)
	}
	if len(cfg.LanesFor("GET", "api.githubcopilot.com", "/chat/completions")) == 0 {
		t.Error("expected the internal lane to match")
	}
}

func TestNonInternalLaneStillBlockedFromReservedHost(t *testing.T) {
	j := `[{"name":"sneaky","placeholder":"P","real":"R",
	       "targets":[{"host":"api.githubcopilot.com"}]}]`
	if _, err := Load(j, ""); err == nil {
		t.Error("a user lane naming a reserved host must be rejected")
	}
}

// Two credentials may share an endpoint: a read-scoped and a write-scoped token
// for the same API, or two organisations. The caller chooses between them by the
// placeholder it carries, so selecting purely on destination would leave all but
// the first unreachable.
func TestTwoCredentialsCanShareAnEndpoint(t *testing.T) {
	j := `[
	  {"name":"read","placeholder":"PH_READ","real":"REAL-READ","targets":[{"host":"api.example","path_prefix":"/v1/"}]},
	  {"name":"write","placeholder":"PH_WRITE","real":"REAL-WRITE","targets":[{"host":"api.example","path_prefix":"/v1/"}]}
	]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	lanes := cfg.LanesFor("GET", "api.example", "/v1/things")
	if len(lanes) != 2 {
		t.Fatalf("got %d candidate lanes, want both", len(lanes))
	}

	header := func(value string) func(string) []string {
		return func(string) []string { return []string{value} }
	}

	if got := Select(lanes, header("Bearer PH_WRITE")); got == nil || got.Name != "write" {
		t.Errorf("carrying the write placeholder selected %v, want the write lane", got)
	}
	if got := Select(lanes, header("Bearer PH_READ")); got == nil || got.Name != "read" {
		t.Errorf("carrying the read placeholder selected %v, want the read lane", got)
	}
	if got := Select(lanes, header("Bearer something-else")); got != nil {
		t.Errorf("carrying no known placeholder selected %v, want no lane", got.Name)
	}
}

// A lane is only selected by its own declared header, so a placeholder sitting in
// some other header does not pull a credential in.
func TestSelectOnlyLooksAtTheDeclaredHeader(t *testing.T) {
	j := `[{"name":"gitlab","placeholder":"PH_GL","real":"R","header":"Private-Token",
	        "targets":[{"host":"gitlab.com"}]}]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	lanes := cfg.LanesFor("GET", "gitlab.com", "/api/v4/projects")

	byName := func(want string) func(string) []string {
		return func(name string) []string {
			if name == want {
				return []string{"PH_GL"}
			}
			return nil
		}
	}
	if got := Select(lanes, byName("private-token")); got == nil {
		t.Error("the placeholder in the declared header should select the lane")
	}
	if got := Select(lanes, byName("authorization")); got != nil {
		t.Error("a placeholder in an undeclared header must not select the lane")
	}
}

// A path prefix grants what it says and nothing adjacent. Without segment-boundary
// matching, /projects/acme would also cover /projects/acmeEVIL, which is a wider
// grant than the author wrote and differs by no visible character.
func TestPathPrefixMatchesOnSegmentBoundaries(t *testing.T) {
	j := `[{"name":"sentry","placeholder":"P","real":"R",
	        "targets":[{"host":"sentry.io","path_prefix":"/api/0/projects/acme"}]}]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/api/0/projects/acme", true},
		{"/api/0/projects/acme/", true},
		{"/api/0/projects/acme/issues", true},
		{"/api/0/projects/acmeEVIL", false},
		{"/api/0/projects/acmeEVIL/secrets", false},
		{"/api/0/projects/acme-staging", false},
	}
	for _, c := range cases {
		if got := len(cfg.LanesFor("GET", "sentry.io", c.path)) > 0; got != c.want {
			t.Errorf("%s: reachable=%v, want %v", c.path, got, c.want)
		}
	}
}

// The point of methods: a credential that can read an endpoint but not write to
// it, even though the token itself could.
func TestMethodsScopeACredentialToReads(t *testing.T) {
	j := `[{"name":"gh","placeholder":"P","real":"R","targets":[
	        {"host":"api.github.com","path_prefix":"/repos/acme/widgets","methods":["GET","HEAD"]}]}]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		method string
		want   bool
	}{
		{"GET", true},
		{"HEAD", true},
		{"get", true}, // methods are compared case-insensitively
		{"POST", false},
		{"PATCH", false},
		{"DELETE", false},
		{"PUT", false},
	}
	for _, c := range cases {
		got := len(cfg.LanesFor(c.method, "api.github.com", "/repos/acme/widgets/issues")) > 0
		if got != c.want {
			t.Errorf("%s: matched=%v, want %v", c.method, got, c.want)
		}
	}
}

func TestNoMethodsMeansAnyMethod(t *testing.T) {
	j := `[{"name":"gh","placeholder":"P","real":"R","targets":[{"host":"api.github.com"}]}]`
	cfg, _ := Load(j, "")
	for _, m := range []string{"GET", "POST", "DELETE", "PATCH"} {
		if len(cfg.LanesFor(m, "api.github.com", "/anything")) == 0 {
			t.Errorf("%s should match when no methods are listed", m)
		}
	}
}

// Two credentials on one endpoint, split by method: a read token for GET and a
// write token for everything else.
func TestReadAndWriteCredentialsOnOneEndpoint(t *testing.T) {
	j := `[
	  {"name":"read","placeholder":"PH_R","real":"REAL-R","targets":[
	    {"host":"api.example","path_prefix":"/v1","methods":["GET"]}]},
	  {"name":"write","placeholder":"PH_W","real":"REAL-W","targets":[
	    {"host":"api.example","path_prefix":"/v1","methods":["POST","PATCH"]}]}
	]`
	cfg, err := Load(j, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	get := cfg.LanesFor("GET", "api.example", "/v1/things")
	if len(get) != 1 || get[0].Name != "read" {
		t.Errorf("GET selected %v, want only the read lane", names(get))
	}
	post := cfg.LanesFor("POST", "api.example", "/v1/things")
	if len(post) != 1 || post[0].Name != "write" {
		t.Errorf("POST selected %v, want only the write lane", names(post))
	}
	if got := cfg.LanesFor("DELETE", "api.example", "/v1/things"); len(got) != 0 {
		t.Errorf("DELETE selected %v, want nothing", names(got))
	}
}

func TestEmptyMethodIsRejected(t *testing.T) {
	j := `[{"name":"gh","placeholder":"P","real":"R","targets":[
	        {"host":"api.github.com","methods":["GET",""]}]}]`
	if _, err := Load(j, ""); err == nil {
		t.Error("an empty method string should be rejected")
	}
}

func names(lanes []*Lane) []string {
	var out []string
	for _, l := range lanes {
		out = append(out, l.Name)
	}
	return out
}
