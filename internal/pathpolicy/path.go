// Package pathpolicy validates request paths without changing the escaped bytes
// that are forwarded upstream.
package pathpolicy

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	maxPathBytes    = 8192
	maxDecodeRounds = 8
)

// Path carries the three representations needed at the gateway boundary.
type Path struct {
	// Raw is the escaped path exactly as the client sent it. This is forwarded.
	Raw string
	// Match differs from Raw only by uppercasing percent-escape hex digits. This
	// makes %2f and %2F equivalent for policy matching without decoding either.
	Match string
	// Decoded is required by Go's URL type so RawPath can preserve Raw.
	Decoded string
}

// Parse validates an escaped path and builds a non-forwarded safety projection
// to detect a complete parent-traversal segment after one or two common decode
// layers. Encoded separators, dots inside names, repeated slashes and ordinary
// percent data remain valid.
func Parse(raw string) (Path, error) {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return Path{}, fmt.Errorf("path must start with /")
	}
	if len(raw) > maxPathBytes {
		return Path{}, fmt.Errorf("path exceeds %d bytes", maxPathBytes)
	}
	if strings.ContainsAny(raw, "?#") {
		return Path{}, fmt.Errorf("path contains a query or fragment delimiter")
	}
	if !utf8.ValidString(raw) {
		return Path{}, fmt.Errorf("path is not valid UTF-8")
	}

	match, err := normalizeEscapes(raw)
	if err != nil {
		return Path{}, err
	}
	decoded, err := url.PathUnescape(match)
	if err != nil {
		return Path{}, fmt.Errorf("path contains an invalid percent escape: %w", err)
	}
	if !utf8.ValidString(decoded) {
		return Path{}, fmt.Errorf("decoded path is not valid UTF-8")
	}
	// Go forwards RawPath only when it is a valid encoding of Path. Refuse any
	// request whose client spelling Go would silently discard and re-escape;
	// otherwise policy, audit and upstream could observe three different paths.
	probe := &url.URL{Path: decoded, RawPath: raw}
	if probe.EscapedPath() != raw {
		return Path{}, fmt.Errorf("path contains characters that must be percent-encoded")
	}
	if err := validateTraversal(match); err != nil {
		return Path{}, err
	}
	return Path{Raw: raw, Match: match, Decoded: decoded}, nil
}

// FromURL validates the exact path from requestURI and confirms Go's decoded URL
// view describes those same bytes.
func FromURL(u *url.URL, requestURI string) (Path, error) {
	if u == nil {
		return Path{}, fmt.Errorf("request URL is missing")
	}
	raw := requestURI
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	path, err := Parse(raw)
	if err != nil {
		return Path{}, err
	}
	if path.Decoded != u.Path {
		return Path{}, fmt.Errorf("escaped and decoded request paths disagree")
	}
	if u.RawPath != "" && u.RawPath != path.Raw {
		return Path{}, fmt.Errorf("request path and RawPath disagree")
	}
	return path, nil
}

// Apply makes u forward Raw while retaining the decoded form Go requires for a
// valid RawPath hint.
func (p Path) Apply(u *url.URL) {
	u.Path = p.Decoded
	u.RawPath = p.Raw
	u.Opaque = ""
}

func normalizeEscapes(raw string) (string, error) {
	var out strings.Builder
	out.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b == 0x7f {
			return "", fmt.Errorf("path contains a control character")
		}
		if b != '%' {
			out.WriteByte(b)
			continue
		}
		if i+2 >= len(raw) {
			return "", fmt.Errorf("path contains an invalid percent escape")
		}
		hi, okHi := hexValue(raw[i+1])
		lo, okLo := hexValue(raw[i+2])
		if !okHi || !okLo {
			return "", fmt.Errorf("path contains an invalid percent escape")
		}
		decoded := byte(hi<<4 | lo)
		if decoded < 0x20 || decoded == 0x7f {
			return "", fmt.Errorf("path contains an encoded control character")
		}
		out.WriteByte('%')
		out.WriteByte(upperHex(hi))
		out.WriteByte(upperHex(lo))
		i += 2
	}
	return out.String(), nil
}

func validateTraversal(path string) error {
	current := path
	for round := 0; round < maxDecodeRounds; round++ {
		projected := strings.ReplaceAll(current, `\`, "/")
		for _, segment := range strings.Split(projected, "/") {
			// Servlet containers may remove matrix/path parameters before
			// normalizing dot segments, so `..;anything` is traversal too.
			if base, _, _ := strings.Cut(segment, ";"); base == ".." {
				return fmt.Errorf("path contains a parent traversal segment after URL decoding")
			}
		}
		next, err := url.PathUnescape(current)
		if err != nil {
			return fmt.Errorf("path contains invalid nested percent encoding")
		}
		if !utf8.ValidString(next) {
			return fmt.Errorf("nested decoded path is not valid UTF-8")
		}
		if next == current {
			return nil
		}
		current = next
	}
	return fmt.Errorf("path has excessive nested percent encoding")
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func upperHex(value byte) byte {
	if value < 10 {
		return '0' + value
	}
	return 'A' + value - 10
}
