// Package config loads the gateway's lane configuration.
//
// A lane binds one placeholder (a worthless string the guest holds) to one real
// credential, plus the set of destinations where that swap is permitted. The real
// credential lives only in this process; the guest never receives it.
package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Target is one place a lane's credential may be used.
//
// PathPrefix is optional. Empty means any path on that host.
type Target struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// Lane binds a placeholder to a real credential for a fixed set of targets.
type Lane struct {
	Name string `json:"name"`
	// Placeholder is what the guest holds and sends. Worthless on its own.
	Placeholder string `json:"placeholder"`
	// Real is the credential we substitute in. Never leaves this process except
	// to the matched upstream.
	Real string `json:"real"`
	// Header is the single header the swap may occur in. Defaults to
	// "Authorization". The swap never touches any other header or the body.
	Header  string   `json:"header,omitempty"`
	Targets []Target `json:"targets"`
	// Internal marks a lane the action creates for itself, such as the Copilot
	// inference lane. Only internal lanes may name a reserved host. This comes
	// from the runner-side configuration and is never influenced by the guest.
	Internal bool `json:"internal,omitempty"`
}

// HeaderName returns the header this lane swaps in, lowercased for comparison.
func (l Lane) HeaderName() string {
	if l.Header == "" {
		return "authorization"
	}
	return strings.ToLower(l.Header)
}

// Matches reports whether host and path fall within this lane's targets.
//
// Host comparison is case-insensitive because DNS names are. Path comparison is
// a prefix with no globbing, deliberately, and it only matches on a path segment
// boundary: /projects/acme covers /projects/acme and /projects/acme/issues, but
// not /projects/acmeEVIL. A raw string prefix would quietly grant a wider scope
// than the author wrote, and the difference is one character they cannot see.
func (l Lane) Matches(host, path string) bool {
	host = strings.ToLower(host)
	for _, t := range l.Targets {
		if strings.ToLower(t.Host) != host {
			continue
		}
		if t.PathPrefix == "" {
			return true
		}
		if !strings.HasPrefix(path, t.PathPrefix) {
			continue
		}
		// A prefix ending in / already lands on a boundary. Otherwise the next
		// character has to be one, or the path has to end there.
		rest := path[len(t.PathPrefix):]
		if strings.HasSuffix(t.PathPrefix, "/") || rest == "" || strings.HasPrefix(rest, "/") {
			return true
		}
	}
	return false
}

// Config is the full gateway configuration.
type Config struct {
	Lanes []Lane
	// EgressAllow are hosts reachable with no credential attached. A request to
	// one of these is forwarded unchanged.
	EgressAllow map[string]bool
}

// reservedHosts may never be named by a non-internal lane.
//
// Not a security control. The upstream is always the host the lane matched, so a
// user lane naming api.githubcopilot.com could not redirect our token anywhere;
// the worst it could do is send that user's own credential to a host they named
// explicitly.
//
// It is rejected because it would be inert. Matching is first-match-wins and the
// action puts the inference lane first, so a user lane on that host is shadowed:
// it never matches, never swaps, and gives no hint as to why. Failing at startup
// is kinder than a credential that silently does nothing.
//
// Note api.github.com is deliberately NOT reserved: pointing a user-supplied
// token at the REST API is a legitimate use wherever MCP has gaps, and blocking
// it would rule out the most accessible scenario there is.
var reservedHosts = map[string]bool{
	"api.githubcopilot.com": true,
}

// Load parses lanes from JSON and the egress allow list from a comma-separated
// string.
//
// Validation is strict and happens once, at startup, so a malformed lane fails
// loudly rather than silently never matching.
func Load(lanesJSON, egressAllow string) (*Config, error) {
	cfg := &Config{EgressAllow: map[string]bool{}}

	if strings.TrimSpace(lanesJSON) != "" {
		if err := json.Unmarshal([]byte(lanesJSON), &cfg.Lanes); err != nil {
			return nil, fmt.Errorf("parsing lanes: %w", err)
		}
	}

	seenName := map[string]bool{}
	seenPlaceholder := map[string]bool{}
	for i, l := range cfg.Lanes {
		if l.Name == "" {
			return nil, fmt.Errorf("lane %d: name is required", i)
		}
		if seenName[l.Name] {
			return nil, fmt.Errorf("lane %q: duplicate name", l.Name)
		}
		seenName[l.Name] = true

		if l.Placeholder == "" {
			return nil, fmt.Errorf("lane %q: placeholder is required", l.Name)
		}
		// Two lanes sharing a placeholder would make the swap ambiguous, since
		// the placeholder is what selects the credential.
		if seenPlaceholder[l.Placeholder] {
			return nil, fmt.Errorf("lane %q: placeholder is already used by another lane", l.Name)
		}
		seenPlaceholder[l.Placeholder] = true

		if l.Real == "" {
			return nil, fmt.Errorf("lane %q: real credential is required", l.Name)
		}
		if len(l.Targets) == 0 {
			return nil, fmt.Errorf("lane %q: at least one target is required", l.Name)
		}
		for j, t := range l.Targets {
			if strings.TrimSpace(t.Host) == "" {
				return nil, fmt.Errorf("lane %q target %d: host is required", l.Name, j)
			}
			if reservedHosts[strings.ToLower(t.Host)] && !l.Internal {
				return nil, fmt.Errorf("lane %q target %d: host %q is reserved", l.Name, j, t.Host)
			}
			if t.PathPrefix != "" && !strings.HasPrefix(t.PathPrefix, "/") {
				return nil, fmt.Errorf("lane %q target %d: path_prefix must start with /", l.Name, j)
			}
		}
	}

	for _, h := range strings.Split(egressAllow, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			cfg.EgressAllow[h] = true
		}
	}

	return cfg, nil
}

// LanesFor returns every lane authorised for host and path, in declaration order.
//
// More than one is normal and is the point of matching on the placeholder as well
// as the destination: a read-scoped and a write-scoped credential can address the
// same endpoint, and the caller chooses between them by which placeholder it
// carries. Selecting purely on destination would make all but the first
// unreachable.
//
// Callers must pass the host they intend to connect to, never a value taken from
// a request header. See proxy.handle.
func (c *Config) LanesFor(host, path string) []*Lane {
	var out []*Lane
	for i := range c.Lanes {
		if c.Lanes[i].Matches(host, path) {
			out = append(out, &c.Lanes[i])
		}
	}
	return out
}

// Select picks the lane the caller actually asked for.
//
// A lane is chosen only when its own placeholder appears in its own declared
// header, so nothing is scanned that we did not already intend to read. Returns
// nil when the destination is authorised but no credential was requested, which
// leaves the request unauthenticated rather than attaching one it did not ask
// for.
func Select(lanes []*Lane, header func(name string) []string) *Lane {
	for _, l := range lanes {
		for _, v := range header(l.HeaderName()) {
			if strings.Contains(v, l.Placeholder) {
				return l
			}
		}
	}
	return nil
}

// AllowsEgress reports whether host may be reached with no credential attached.
func (c *Config) AllowsEgress(host string) bool {
	return c.EgressAllow[strings.ToLower(host)]
}
