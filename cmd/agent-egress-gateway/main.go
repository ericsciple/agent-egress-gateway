// Command agent-gateway is the credential gateway used by the agent step
// prototypes. It terminates TLS for intercepted connections, swaps a placeholder
// for a real credential on authorised destinations, and forwards the request.
//
// The real credential lives only in this process. The guest holds a placeholder,
// which is worth nothing on its own.
//
// # Two topologies
//
// intercept (default)
//
//	Connections arrive from a netfilter REDIRECT rule and this process
//	terminates TLS itself. Used by agent-microvm, where the rule sits on the
//	runner, outside the guest's reach.
//
// runner
//
//	TLS has already been terminated by a shim inside the guest, and the request
//	arrives over the dev tunnel as ordinary HTTP naming its destination in
//	X-Agent-Gateway-Host. Used by agent-sandbox, because the tunnel carries HTTP
//	request/response rather than a raw byte stream.
//
// In both, the credential and the upstream dial stay in this process, so the
// guest never holds a real credential either way.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/ericsciple/agent-egress-gateway/internal/ca"
	"github.com/ericsciple/agent-egress-gateway/internal/config"
	"github.com/ericsciple/agent-egress-gateway/internal/proxy"
)

func main() {
	var (
		listen   = flag.String("listen", ":8080", "address to listen on")
		mode     = flag.String("mode", "intercept", "topology: intercept (terminate TLS here) or runner (TLS already terminated in the guest)")
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

	switch *mode {
	case "runner":
		if err := http.ListenAndServe(*listen, p.RunnerHandler()); err != nil {
			log.Fatalf("[gateway] serving: %v", err)
		}
	case "intercept":
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("[gateway] listening on %s: %v", *listen, err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[gateway] accept: %v", err)
				continue
			}
			go func(c net.Conn) {
				dst, err := proxy.OriginalDestination(c)
				if err != nil {
					dst = fmt.Sprintf("unknown (%v)", err)
				}
				p.Serve(c, dst)
			}(conn)
		}
	default:
		log.Fatalf("[gateway] unknown mode %q: want intercept or runner", *mode)
	}
}
