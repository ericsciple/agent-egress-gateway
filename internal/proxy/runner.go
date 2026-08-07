package proxy

import (
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/ericsciple/agent-egress-gateway/internal/config"
)

// HostHeader carries the destination the guest was trying to reach.
//
// The guest chooses this value, and that is safe, because it is also the host we
// dial. A guest naming a lane target simply has that lane's credential sent to
// that target, which is what the lane authorises. The attack this design has to
// prevent is the matched host and the connected host *diverging*, and they cannot
// here: both come from this one value.
const HostHeader = "X-Agent-Gateway-Host"

// hopByHop headers are per-connection and must not be forwarded. The tunnel's own
// auth headers are stripped too: they are for the relay, not the upstream, and
// forwarding them would leak the tunnel token to whoever we dial.
var stripFromGuest = map[string]bool{
	"connection":                       true,
	"keep-alive":                       true,
	"proxy-authenticate":               true,
	"proxy-authorization":              true,
	"te":                               true,
	"trailer":                          true,
	"transfer-encoding":                true,
	"upgrade":                          true,
	"x-tunnel-authorization":           true,
	"x-tunnel-skip-anti-phishing-page": true,
	"x-forwarded-for":                  true,
	"x-forwarded-host":                 true,
	"x-forwarded-proto":                true,
}

// RunnerHandler serves the sandbox topology, where TLS has already been
// terminated by a shim inside the guest and the request arrives over the dev
// tunnel as ordinary HTTP.
//
// The tunnel is HTTP request/response, not a raw byte channel, which is why the
// guest cannot simply relay the TLS stream here for us to terminate.
func (p *Proxy) RunnerHandler() http.Handler {
	var rt http.RoundTripper = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConnsPerHost:   4,
	}
	if p.Transport != nil {
		rt = p.Transport
	}
	client := &http.Client{
		Timeout:   5 * time.Minute,
		Transport: rt,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Following a redirect could carry the credential to a host the lane
			// never authorised. Hand the redirect back to the caller instead.
			return http.ErrUseLastResponse
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		host := strings.ToLower(strings.TrimSpace(r.Header.Get(HostHeader)))
		if host == "" {
			p.Log("rejected: no " + HostHeader)
			http.Error(w, "missing "+HostHeader, http.StatusBadRequest)
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		// Host and path decide which credentials are permitted here; the
		// placeholder decides which of them the caller actually asked for. Both
		// matter: two credentials may share an endpoint.
		lanes := p.cfg.LanesFor(host, r.URL.Path)
		lane := config.Select(lanes, func(name string) []string {
			return r.Header.Values(textproto.CanonicalMIMEHeaderKey(name))
		})
		switch {
		case lane != nil:
			swap(r.Header, lane)
			p.Log(r.Method + " " + host + r.URL.Path + " lane=" + lane.Name + " swapped")
		case len(lanes) > 0:
			p.Log(r.Method + " " + host + r.URL.Path + " allowed, no placeholder presented")
		case p.cfg.AllowsEgress(host):
			p.Log(r.Method + " " + host + r.URL.Path + " allowed, no credential")
		default:
			p.Log(r.Method + " " + host + r.URL.Path + " blocked")
			http.Error(w, "destination not allowed", http.StatusForbidden)
			return
		}

		// The one place an upstream is chosen, and it is the host we matched on.
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method,
			"https://"+host+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "building upstream request", http.StatusInternalServerError)
			return
		}
		for k, vs := range r.Header {
			if stripFromGuest[strings.ToLower(k)] || strings.EqualFold(k, HostHeader) {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Host = host

		resp, err := client.Do(outReq)
		if err != nil {
			p.Log(host + ": upstream failed: " + err.Error())
			http.Error(w, "upstream connection failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for k, vs := range resp.Header {
			if stripFromGuest[strings.ToLower(k)] {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
}
