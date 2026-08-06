package ca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestNewIsFastAndUsable(t *testing.T) {
	start := time.Now()
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The whole point of generating in-process is that it is not an 8 second
	// wait for a proxy to write a file. Generous bound; typical is ~1ms.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("CA generation took %v, expected well under a second", elapsed)
	}

	block, _ := pem.Decode(c.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CertPEM did not produce a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing exported CA: %v", err)
	}
	if !cert.IsCA {
		t.Error("exported certificate is not a CA")
	}
}

func TestLeafChainsToCA(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf, err := c.LeafFor("sentry.io")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CertPEM()) {
		t.Fatal("could not add CA to pool")
	}
	if _, err := parsed.Verify(x509.VerifyOptions{DNSName: "sentry.io", Roots: roots}); err != nil {
		t.Errorf("leaf did not verify against its own CA: %v", err)
	}

	// A leaf minted for one host must not be accepted for another.
	if _, err := parsed.Verify(x509.VerifyOptions{DNSName: "evil.example", Roots: roots}); err == nil {
		t.Error("leaf for sentry.io wrongly verified for evil.example")
	}
}

func TestLeafIsCached(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a, err := c.LeafFor("sentry.io")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	b, err := c.LeafFor("sentry.io")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if a != b {
		t.Error("expected the cached certificate to be reused")
	}
}

func TestLeafForIPAddress(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf, err := c.LeafFor("10.1.2.3")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	if len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "10.1.2.3" {
		t.Errorf("expected an IP SAN, got DNS=%v IP=%v", parsed.DNSNames, parsed.IPAddresses)
	}
}
