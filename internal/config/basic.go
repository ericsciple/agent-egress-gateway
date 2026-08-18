package config

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// HTTP Basic credentials are `base64(user:password)`, so a placeholder carried in
// one of those two fields never appears literally in the header value. Without
// decoding, a lane would neither be selected nor swapped, and the request would go
// out still holding the worthless placeholder — failing at the upstream as a 401
// that gives no hint why.
//
// Basic is common enough in ordinary tooling (`curl -u`, git over HTTPS, plenty of
// SDKs) that "use your existing script unchanged" is not true without this.
//
// The scheme is matched case-insensitively because RFC 7235 defines it that way,
// and the exact spacing is preserved on re-encode so we return the header as close
// to how it arrived as possible.
var basicRE = regexp.MustCompile(`^([Bb][Aa][Ss][Ii][Cc])([ \t]+)([A-Za-z0-9+/=]+)([ \t]*)$`)

// decodeBasic returns the decoded `user:password` of a Basic credential.
//
// Reports ok=false for anything that is not a well-formed Basic credential, which
// leaves the value untouched by the caller. Non-UTF-8 payloads are refused rather
// than decoded: a replacement inside binary would corrupt it, and a credential that
// is not text cannot contain our placeholder anyway.
func decodeBasic(value string) (scheme, space, decoded, trailing string, ok bool) {
	m := basicRE.FindStringSubmatch(value)
	if m == nil {
		return "", "", "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil || !utf8.Valid(raw) {
		return "", "", "", "", false
	}
	return m[1], m[2], string(raw), m[4], true
}

// encodeBasic rebuilds a Basic credential around a replaced payload.
func encodeBasic(scheme, space, decoded, trailing string) string {
	return scheme + space + base64.StdEncoding.EncodeToString([]byte(decoded)) + trailing
}

// headerCarries reports whether value carries placeholder, either literally or
// inside a Basic credential.
func headerCarries(value, placeholder string) bool {
	if strings.Contains(value, placeholder) {
		return true
	}
	if _, _, decoded, _, ok := decodeBasic(value); ok {
		return strings.Contains(decoded, placeholder)
	}
	return false
}

// SwapValue substitutes real for placeholder in one header value, transparently
// handling a Basic credential.
//
// Returns the value unchanged when the placeholder is not present, so a caller can
// use the returned bool to decide whether anything was rewritten at all.
//
// The substitution is confined to this one value; the body and every other header
// are never touched. Widening it would create an exfiltration path, because a caller
// could park the placeholder in a field the upstream stores or echoes and read the
// real credential back out.
func SwapValue(value, placeholder, real string) (string, bool) {
	if strings.Contains(value, placeholder) {
		return strings.ReplaceAll(value, placeholder, real), true
	}
	scheme, space, decoded, trailing, ok := decodeBasic(value)
	if !ok || !strings.Contains(decoded, placeholder) {
		return value, false
	}
	return encodeBasic(scheme, space, strings.ReplaceAll(decoded, placeholder, real), trailing), true
}
