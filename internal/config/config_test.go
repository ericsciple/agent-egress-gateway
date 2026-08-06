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
		lane := cfg.LaneFor(c.host, c.path)
		got := ""
		if lane != nil {
			got = lane.Name
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
	if cfg.LaneFor("api.github.com", "/repos/acme/thing") == nil {
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
	if cfg.LaneFor("api.githubcopilot.com", "/chat/completions") == nil {
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
