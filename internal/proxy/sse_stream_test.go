package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
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
