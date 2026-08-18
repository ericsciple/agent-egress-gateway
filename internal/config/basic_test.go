package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// HTTP Basic hides the credential inside base64, so these cover the two things that
// have to stay true: a placeholder in either field is found and replaced, and
// nothing that is not a well-formed Basic credential is ever rewritten.

const ph = "aph_PLACEHOLDER"
const real = "s3cret-value"

func basic(payload string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
}

func TestSwapValueReplacesPlaceholderInBasicPassword(t *testing.T) {
	// `curl -u user:$TOKEN` and most SDKs put the credential in the password.
	got, did := SwapValue(basic("user:"+ph), ph, real)
	if !did {
		t.Fatal("placeholder inside a Basic credential was not swapped")
	}
	if got == basic("user:"+ph) {
		t.Fatal("value was reported swapped but did not change")
	}
	if decoded := decodeOrFail(t, got); decoded != "user:"+real {
		t.Fatalf("decoded payload = %q, want %q", decoded, "user:"+real)
	}
}

func TestSwapValueReplacesPlaceholderInBasicUsername(t *testing.T) {
	// The token-as-username form, e.g. git over HTTPS and GitHub's
	// `<token>:x-oauth-basic`.
	got, did := SwapValue(basic(ph+":x-oauth-basic"), ph, real)
	if !did {
		t.Fatal("placeholder in the username position was not swapped")
	}
	if decoded := decodeOrFail(t, got); decoded != real+":x-oauth-basic" {
		t.Fatalf("decoded payload = %q", decoded)
	}
}

func TestSwapValueStillHandlesPlainBearer(t *testing.T) {
	got, did := SwapValue("Bearer "+ph, ph, real)
	if !did || got != "Bearer "+real {
		t.Fatalf("plain substitution regressed: %q (swapped=%v)", got, did)
	}
}

func TestSwapValueLeavesUnrelatedValuesAlone(t *testing.T) {
	for _, v := range []string{
		"Bearer somebody-elses-token",
		basic("user:somebody-elses-password"),
		"Basic not$valid$base64",
		"Basic",
		"",
	} {
		got, did := SwapValue(v, ph, real)
		if did || got != v {
			t.Fatalf("value %q was rewritten to %q", v, got)
		}
	}
}

func TestSwapValueNeverLeaksTheCredentialIntoAnUnmatchedValue(t *testing.T) {
	// The important negative: a Basic credential that does NOT carry our
	// placeholder must come out byte-identical, with no trace of the real value.
	in := basic("user:their-own-password")
	got, did := SwapValue(in, ph, real)
	if did {
		t.Fatal("swapped a credential that did not carry the placeholder")
	}
	if strings.Contains(got, real) {
		t.Fatal("the real credential leaked into an unmatched value")
	}
}

func TestDecodeBasicRefusesNonUTF8(t *testing.T) {
	// Replacing inside binary would corrupt it, and a non-text credential cannot
	// contain the placeholder anyway.
	v := "Basic " + base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00})
	if _, _, _, _, ok := decodeBasic(v); ok {
		t.Fatal("decoded a non-UTF-8 payload")
	}
}

func TestDecodeBasicIsCaseInsensitiveAndPreservesSpacing(t *testing.T) {
	// RFC 7235 makes the scheme case-insensitive; we echo back what we were given
	// rather than normalising it.
	in := "bAsIc\t" + base64.StdEncoding.EncodeToString([]byte("user:"+ph))
	got, did := SwapValue(in, ph, real)
	if !did {
		t.Fatal("case-insensitive scheme was not recognised")
	}
	if !strings.HasPrefix(got, "bAsIc\t") {
		t.Fatalf("scheme or spacing was not preserved: %q", got)
	}
}

func TestSelectFindsALaneWhosePlaceholderIsInsideBasic(t *testing.T) {
	// Selection and substitution have to agree: if only the swap decoded Basic, no
	// lane would ever be selected for one and the credential would silently never
	// be attached.
	lane := &Lane{Name: "l", Placeholder: ph, Real: real}
	got := Select([]*Lane{lane}, func(string) []string {
		return []string{basic("user:" + ph)}
	})
	if got != lane {
		t.Fatal("no lane selected for a placeholder carried inside Basic")
	}
}

func TestSelectIgnoresABasicCredentialThatIsNotOurs(t *testing.T) {
	lane := &Lane{Name: "l", Placeholder: ph, Real: real}
	got := Select([]*Lane{lane}, func(string) []string {
		return []string{basic("user:someone-elses")}
	})
	if got != nil {
		t.Fatal("selected a lane for a credential that is not ours")
	}
}

func decodeOrFail(t *testing.T, header string) string {
	t.Helper()
	_, _, decoded, _, ok := decodeBasic(header)
	if !ok {
		t.Fatalf("could not decode %q", header)
	}
	return decoded
}
