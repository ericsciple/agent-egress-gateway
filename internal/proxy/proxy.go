// Package proxy terminates TLS for intercepted connections, swaps a lane's
// placeholder for its real credential, and forwards the request upstream.
//
// # The rule that matters
//
// The host used to select a lane and the host used to open the upstream
// connection are the same value, taken from the TLS SNI. Nothing supplied in a
// request header, and no destination address supplied by the guest, can make
// those two disagree.
//
// This closes a class of attack that is otherwise easy to reintroduce. If a lane
// were matched on the Host header while the connection went to an address chosen
// by the guest, a caller could claim a lane target it is authorised for and have
// the real credential delivered somewhere else entirely.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ericsciple/agent-egress-gateway/internal/ca"
	"github.com/ericsciple/agent-egress-gateway/internal/config"
	"github.com/ericsciple/agent-egress-gateway/internal/pathpolicy"
)

// DialFunc opens a connection to an upstream host. Injected so tests can avoid
// real network access.
type DialFunc func(host string) (net.Conn, error)

// Proxy handles intercepted connections.
type Proxy struct {
	cfg *config.Config
	ca  *ca.CA
	// Dial opens the upstream connection in intercept mode. It receives the host
	// the lane was matched on and nothing else, which is what keeps the two from
	// diverging.
	Dial DialFunc
	// Transport, when set, replaces the default upstream transport in runner
	// mode. Tests use it to observe what was actually dialled; production leaves
	// it nil.
	Transport http.RoundTripper
	// Log receives one audit line per request.
	Log func(string)
}

// New returns a Proxy that dials real upstreams over verified TLS.
func New(cfg *config.Config, authority *ca.CA) *Proxy {
	return &Proxy{
		cfg:  cfg,
		ca:   authority,
		Dial: dialTLS,
		Log:  func(s string) { log.Println("[gateway]", s) },
	}
}

// dialTLS connects to host over TLS with full certificate verification.
//
// ServerName is set from the same host we dial, so a certificate valid for some
// other name cannot satisfy this connection.
func dialTLS(host string) (net.Conn, error) {
	return tls.Dial("tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
}

// Serve handles one intercepted client connection to completion.
//
// originalDst is used only for logging. It is deliberately not used to choose a
// lane or an upstream, because in the sandbox topology the redirect happens
// inside the guest, where a root process could set it to anything.
func (p *Proxy) Serve(client net.Conn, originalDst string) {
	defer client.Close()

	var sni string
	tlsConn := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = hello.ServerName
			if sni == "" {
				return nil, fmt.Errorf("client sent no SNI")
			}
			return p.ca.LeafFor(sni)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		p.Log(fmt.Sprintf("handshake failed (original_dst=%s): %v", originalDst, err))
		return
	}
	defer tlsConn.Close()

	// SNI is the only host value used from here on.
	host := strings.ToLower(sni)

	var upstream net.Conn
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Log(fmt.Sprintf("%s: reading request: %v", host, err))
			}
			return
		}

		if !config.MethodSupported(req.Method) {
			p.Log(fmt.Sprintf("%s %s rejected: unsupported method", req.Method, host))
			writeError(tlsConn, http.StatusMethodNotAllowed, "TRACE is not supported")
			return
		}

		// A request whose Host header disagrees with the TLS name it arrived
		// under is refused rather than reconciled. Allowing the two to differ is
		// exactly how a lane could be matched on one host while the connection
		// went to another.
		if h := hostOnly(req.Host); h != "" && !strings.EqualFold(h, host) {
			p.Log(fmt.Sprintf("%s: refused, Host header %q disagrees with TLS name", host, req.Host))
			writeError(tlsConn, http.StatusForbidden, "host header does not match the TLS server name")
			return
		}

		requestPath, err := pathpolicy.FromURL(req.URL, req.RequestURI)
		if err != nil {
			p.Log(fmt.Sprintf("%s %s%s rejected: %v", req.Method, host, requestPathForLog(req.RequestURI), err))
			writeError(tlsConn, http.StatusBadRequest, "request path rejected: "+err.Error())
			return
		}

		requestPath.Apply(req.URL)

		// Method, host and path decide which credentials are permitted here; the
		// placeholder decides which of them the caller actually asked for. Both
		// matter: two credentials may share an endpoint.
		lanes := p.cfg.LanesFor(req.Method, host, requestPath.Match)
		lane := config.Select(lanes, func(name string) []string {
			return req.Header.Values(textproto.CanonicalMIMEHeaderKey(name))
		})
		switch {
		case lane != nil:
			swap(req.Header, lane)
			p.Log(fmt.Sprintf("%s %s%s lane=%s swapped", req.Method, host, requestPath.Raw, lane.Name))
		case len(lanes) > 0:
			// The destination is authorised but the caller did not ask for a
			// credential, so the request goes on unauthenticated.
			p.Log(fmt.Sprintf("%s %s%s allowed, no placeholder presented", req.Method, host, requestPath.Raw))
		case p.cfg.AllowsEgress(host):
			p.Log(fmt.Sprintf("%s %s%s allowed, no credential", req.Method, host, requestPath.Raw))
		default:
			p.Log(fmt.Sprintf("%s %s%s blocked", req.Method, host, requestPath.Raw))
			writeError(tlsConn, http.StatusForbidden, "destination not allowed")
			return
		}

		if upstream == nil {
			// The one and only place an upstream is chosen, and it can only be
			// the host we matched on.
			upstream, err = p.Dial(host)
			if err != nil {
				p.Log(fmt.Sprintf("%s: dialing upstream: %v", host, err))
				writeError(tlsConn, http.StatusBadGateway, "upstream connection failed")
				return
			}
		}

		req.Host = host
		if err := req.Write(upstream); err != nil {
			p.Log(fmt.Sprintf("%s: writing upstream: %v", host, err))
			writeError(tlsConn, http.StatusBadGateway, "upstream write failed")
			return
		}

		upstreamReader := bufio.NewReader(upstream)
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			p.Log(fmt.Sprintf("%s: reading upstream response: %v", host, err))
			writeError(tlsConn, http.StatusBadGateway, "upstream read failed")
			return
		}

		// A protocol upgrade ends the HTTP conversation: after 101 the bytes on
		// this connection are no longer requests and responses, and both sides may
		// speak at once.
		//
		// Relaying it as though it were an ordinary response deadlocks. resp.Write
		// blocks copying upstream->client for as long as the peer holds the stream
		// open, so nothing ever reads client->upstream, and a client waiting for a
		// reply to a frame it has already sent waits forever. That is a hang with
		// no error anywhere, which is exactly how it presented: a run that sat
		// silent until its timeout.
		//
		// Handing the connection over is safe here because the decision has already
		// been made: this socket is pinned to the host we matched, the credential
		// swap has happened on the upgrade request itself, and what follows carries
		// no paths or methods left to authorise.
		if resp.StatusCode == http.StatusSwitchingProtocols {
			p.Log(fmt.Sprintf("%s %s%s upgraded to %s", req.Method, host, requestPath.Raw, resp.Header.Get("Upgrade")))
			if err := writeHead(tlsConn, resp); err != nil {
				return
			}
			// Both buffered readers may already hold bytes that arrived with the
			// head; copying from the raw sockets instead would silently drop them.
			relay(tlsConn, reader, upstream, upstreamReader)
			return
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if req.Close || resp.Close {
			return
		}
	}
}

func requestPathForLog(requestURI string) string {
	path := requestURI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	const max = 512
	if len(path) > max {
		return path[:max] + "...(truncated)"
	}
	return path
}

// swap replaces the lane's placeholder with its real credential, in that lane's
// declared header and nowhere else.
//
// The body and every other header are left exactly as sent. Swapping more widely
// would create an exfiltration path: a caller could put the placeholder in a
// field the upstream persists, have the real credential substituted into it, and
// read it back out.
//
// A Basic credential is decoded, substituted and re-encoded, since the placeholder
// sits inside base64 there rather than in the header value itself.
func swap(h http.Header, lane *config.Lane) bool {
	name := textproto.CanonicalMIMEHeaderKey(lane.HeaderName())
	values, ok := h[name]
	if !ok {
		return false
	}
	swapped := false
	for i, v := range values {
		if replaced, did := config.SwapValue(v, lane.Placeholder, lane.Real); did {
			values[i] = replaced
			swapped = true
		}
	}
	return swapped
}

// hostOnly strips any port from a Host header value.
func hostOnly(h string) string {
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func writeError(w io.Writer, status int, msg string) {
	body := fmt.Sprintf("{\"error\":%q}\n", msg)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

// writeHead writes a response's status line and headers, and nothing else.
//
// Used for an upgrade, where there is no body to write and the connection is about
// to stop being HTTP. resp.Write cannot be used: it would try to relay a body that
// never ends.
func writeHead(w io.Writer, resp *http.Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	if err := resp.Header.Write(&b); err != nil {
		return err
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// relay copies bytes in both directions until either side finishes.
//
// Returning as soon as ONE direction ends is deliberate: the caller closes both
// connections on return, which unblocks the other copy. Waiting for both would
// leave a half-closed stream holding the connection open until the run timed out.
func relay(client io.Writer, clientSrc io.Reader, upstream io.Writer, upstreamSrc io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, clientSrc); done <- struct{}{} }()
	go func() { io.Copy(client, upstreamSrc); done <- struct{}{} }()
	<-done
}
