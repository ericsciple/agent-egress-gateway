package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ericsciple/agent-egress-gateway/internal/ca"
	"github.com/ericsciple/agent-egress-gateway/internal/config"
)

// Does the intercept path stream a server-sent-event response incrementally, or
// does it hold the bytes until the upstream closes? The agent's inference response
// arrives this way, so buffering it reads to the caller as a hang.
func TestInterceptStreamsSSEIncrementally(t *testing.T) {
	cfg, _ := config.Load(`[]`, "sse.test")
	authority, _ := ca.New()
	p := New(cfg, authority)
	p.Log = func(string) {}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				http.ReadRequest(bufio.NewReader(c))
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
				for i := 0; i < 3; i++ {
					msg := fmt.Sprintf("data: tick%d\n\n", i)
					fmt.Fprintf(c, "%x\r\n%s\r\n", len(msg), msg)
					time.Sleep(300 * time.Millisecond)
				}
				io.WriteString(c, "0\r\n\r\n")
			}(c)
		}
	}()
	p.Dial = func(string) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(authority.CertPEM())

	client, server := net.Pipe()
	go p.Serve(server, "sse.test:443")
	tc := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "sse.test", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	fmt.Fprintf(tc, "GET /responses HTTP/1.1\r\nHost: sse.test\r\n\r\n")

	br := bufio.NewReader(tc)
	// Read past the response head.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading head: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	start := time.Now()
	firstByte := make(chan time.Duration, 1)
	go func() {
		b := make([]byte, 1)
		if _, err := io.ReadFull(br, b); err == nil {
			firstByte <- time.Since(start)
		}
	}()

	select {
	case d := <-firstByte:
		// The first event is available immediately; the stream does not end for
		// ~900ms. Anything close to that means we waited for the whole body.
		if d > 250*time.Millisecond {
			t.Fatalf("first byte took %v — the stream is being buffered, not relayed", d)
		}
		t.Logf("first byte after %v (streaming)", d)
	case <-time.After(3 * time.Second):
		t.Fatal("no data at all — the stream stalled")
	}
}

// A protocol upgrade turns the connection into a two-way byte stream. Relaying it
// as an ordinary response deadlocks: the upstream copy blocks for as long as the
// peer holds the stream open, so nothing reads the client's side and a client
// waiting on a reply waits forever. That is what made runs sit silent until their
// timeout, with no error logged anywhere.
func TestUpgradedConnectionRelaysBothWays(t *testing.T) {
	cfg, _ := config.Load(`[]`, "ws.test")
	authority, _ := ca.New()
	p := New(cfg, authority)
	p.Log = func(string) {}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				http.ReadRequest(br)
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				// Echo whatever the client sends AFTER the upgrade. A one-way
				// relay never delivers it, so this never fires.
				buf := make([]byte, 64)
				n, err := br.Read(buf)
				if err != nil {
					return
				}
				c.Write(append([]byte("echo:"), buf[:n]...))
			}(c)
		}
	}()
	p.Dial = func(string) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(authority.CertPEM())

	client, server := net.Pipe()
	go p.Serve(server, "ws.test:443")
	tc := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "ws.test", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	fmt.Fprintf(tc, "GET /responses HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")

	br := bufio.NewReader(tc)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("status line = %q, err = %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Send a frame and expect the echo. Without a bidirectional relay this blocks.
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("writing after upgrade: %v", err)
	}
	got := make([]byte, 9)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("no echo after upgrade (the relay is one-way): %v", err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("got %q, want %q", got, "echo:ping")
	}
}
