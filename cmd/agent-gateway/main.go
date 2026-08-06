// Command agent-gateway is the credential gateway used by the agent step
// prototypes. It terminates TLS for intercepted connections, swaps a placeholder
// for a real credential on authorised destinations, and forwards the request.
//
// The real credential lives only in this process. The guest holds a placeholder,
// which is worth nothing on its own.
//
// # Two front doors
//
// redirect (default)
//
//	Connections arrive from a netfilter REDIRECT rule. Used by agent-microvm,
//	where the rule is on the runner, and by agent-sandbox, where it is inside
//	the guest.
//
// preamble
//
//	Connections arrive over a relay that cannot preserve the original
//	destination, so the client sends one line naming it before the TLS stream
//	begins. The value is logged and never trusted for routing.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/github/agent-gateway/internal/ca"
	"github.com/github/agent-gateway/internal/config"
	"github.com/github/agent-gateway/internal/proxy"
)

func main() {
	var (
		listen   = flag.String("listen", ":8080", "address to listen on")
		mode     = flag.String("mode", "redirect", "how connections arrive: redirect or preamble")
		caOut    = flag.String("ca-out", "", "write the CA certificate here, for the guest trust store")
		lanesEnv = flag.String("lanes-env", "GW_LANES", "environment variable holding the lane JSON")
	)
	flag.Parse()

	cfg, err := config.Load(os.Getenv(*lanesEnv), os.Getenv("GW_EGRESS_ALLOW"))
	if err != nil {
		log.Fatalf("[gateway] configuration: %v", err)
	}

	authority, err := ca.New()
	if err != nil {
		log.Fatalf("[gateway] generating CA: %v", err)
	}
	if *caOut != "" {
		if err := os.WriteFile(*caOut, authority.CertPEM(), 0o644); err != nil {
			log.Fatalf("[gateway] writing CA to %s: %v", *caOut, err)
		}
		log.Printf("[gateway] CA written to %s", *caOut)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("[gateway] listening on %s: %v", *listen, err)
	}

	p := proxy.New(cfg, authority)

	log.Printf("[gateway] listening on %s mode=%s", *listen, *mode)
	log.Printf("[gateway] %d lane(s), %d egress-allow host(s)", len(cfg.Lanes), len(cfg.EgressAllow))
	for _, l := range cfg.Lanes {
		var targets []string
		for _, t := range l.Targets {
			targets = append(targets, t.Host+t.PathPrefix)
		}
		// Never the credential or the placeholder: only the shape of the lane.
		log.Printf("[gateway]   lane %q header=%s targets=%s", l.Name, l.HeaderName(), strings.Join(targets, ","))
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[gateway] accept: %v", err)
			continue
		}
		go serve(p, conn, *mode)
	}
}

func serve(p *proxy.Proxy, conn net.Conn, mode string) {
	switch mode {
	case "preamble":
		// One line naming the destination the guest was headed for, then the TLS
		// stream. Diagnostic only.
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			log.Printf("[gateway] reading preamble: %v", err)
			conn.Close()
			return
		}
		p.Serve(&preambleConn{Conn: conn, reader: br}, strings.TrimSpace(line))
	default:
		dst, err := proxy.OriginalDestination(conn)
		if err != nil {
			dst = fmt.Sprintf("unknown (%v)", err)
		}
		p.Serve(conn, dst)
	}
}

// preambleConn hands back the bytes the preamble reader buffered ahead of the
// TLS stream.
type preambleConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *preambleConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
