#!/usr/bin/env python3
"""Egress interceptor: the guest-side half of the egress gateway.

Runs *inside* the sandbox. An iptables rule redirects outbound :443 here, this
terminates TLS with a CA it generates locally, and forwards the plaintext request
over the dev tunnel to the egress gateway on the runner, naming the intended
destination in X-Agent-Gateway-Host.

What this is not
----------------
This is not a security boundary. The guest is root and can kill this process,
drop the iptables rule, or replace this file. It holds no credentials: the CA it
mints is its own, and the real credential only ever exists on the runner. Its job
is transparency, so an unmodified script calling https://sentry.io keeps working.

Bypassing it gains nothing. Sandbox egress is default-deny with only the tunnel
reachable, so traffic that skips the shim reaches nothing at all.

Why TLS is terminated here rather than on the runner
----------------------------------------------------
The dev tunnel carries HTTP request/response, not a raw byte stream, so the TLS
stream cannot simply be relayed to the runner for termination there.

Why the guest naming its own destination is safe
------------------------------------------------
The runner matches the lane on X-Agent-Gateway-Host and dials that same host.
Naming a lane target only sends that lane's credential to that target, which is
what the lane authorises. The attack worth preventing is the matched host and the
connected host diverging, and here one value drives both.

Requires Python 3.7+ (ssl.SSLContext.sni_callback) and the openssl CLI.
"""

import http.client
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import urllib.parse

SO_ORIGINAL_DST = 80

LISTEN_PORT = int(os.environ.get("SHIM_PORT", "8443"))
TUNNEL_URL = os.environ.get("SHIM_TUNNEL_URL", "")
TUNNEL_TOKEN = os.environ.get("SHIM_TUNNEL_TOKEN", "")
CERT_DIR = os.environ.get("SHIM_CERT_DIR", "/tmp/agent-shim")
# The tunnel's own hostname. Traffic to it is excluded from the redirect by
# address, but DNS can hand back an address that exclusion missed. Refusing it
# here turns that into a clear error instead of an infinite loop through
# ourselves.
TUNNEL_HOST = urllib.parse.urlsplit(os.environ.get("SHIM_TUNNEL_URL", "")).hostname or ""
HOST_HEADER = "X-Agent-Gateway-Host"

# Headers belonging to the guest's own hop, which must not be forwarded.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


def log(msg):
    print("[interceptor] %s" % msg, file=sys.stderr, flush=True)


def preflight():
    if sys.version_info < (3, 7):
        sys.exit("[interceptor] python 3.7+ required (ssl sni_callback); found %d.%d"
                 % sys.version_info[:2])
    if not TUNNEL_URL or not TUNNEL_TOKEN:
        sys.exit("[interceptor] SHIM_TUNNEL_URL and SHIM_TUNNEL_TOKEN are required")
    try:
        subprocess.run(["openssl", "version"], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.exit("[interceptor] the openssl CLI is required: %s" % exc)


class Authority:
    """Generates a CA once, then mints and caches a leaf certificate per SNI name."""

    def __init__(self, directory):
        self.dir = directory
        self.key = os.path.join(directory, "ca.key")
        self.crt = os.path.join(directory, "ca.crt")
        self._contexts = {}
        self._lock = threading.Lock()
        os.makedirs(directory, exist_ok=True)
        self._generate_ca()

    def _generate_ca(self):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", self.key, "-out", self.crt,
             "-days", "1", "-subj", "/CN=agent egress interceptor"],
            check=True, capture_output=True)
        log("CA generated at %s" % self.crt)

    def context_for(self, host):
        with self._lock:
            if host in self._contexts:
                return self._contexts[host]

            key = os.path.join(self.dir, "%s.key" % host)
            crt = os.path.join(self.dir, "%s.crt" % host)
            csr = os.path.join(self.dir, "%s.csr" % host)
            subprocess.run(
                ["openssl", "req", "-new", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", key, "-out", csr, "-subj", "/CN=%s" % host],
                check=True, capture_output=True)
            subprocess.run(
                ["openssl", "x509", "-req", "-in", csr,
                 "-CA", self.crt, "-CAkey", self.key, "-CAcreateserial",
                 "-out", crt, "-days", "1", "-extfile", "/dev/stdin"],
                check=True, capture_output=True,
                input=("subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n" % host).encode())

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            self._contexts[host] = ctx
            return ctx


def original_destination(sock):
    """The address this connection was headed for before iptables redirected it.

    Diagnostic only. Routing uses the SNI name, because this value comes from the
    guest's own kernel, where a root process controls the rules.
    """
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, addr = struct.unpack("!2xH4s8x", raw)
        return "%s:%d" % (socket.inet_ntoa(addr), port)
    except OSError:
        return "unknown"


def read_request(stream):
    """Parse a request line plus headers, returning them with any body."""
    request_line = stream.readline().decode("latin-1").rstrip("\r\n")
    if not request_line:
        return None
    parts = request_line.split(" ")
    if len(parts) != 3:
        return None
    method, target, _version = parts

    headers = []
    while True:
        line = stream.readline().decode("latin-1")
        if line in ("\r\n", "\n", ""):
            break
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))

    body = b""
    for name, value in headers:
        if name.lower() == "content-length" and value.isdigit():
            body = stream.read(int(value))
            break
    return method, target, headers, body


def forward(method, target, headers, body, host):
    """Send the request to the runner-side gateway through the dev tunnel."""
    url = urllib.parse.urlsplit(TUNNEL_URL)
    conn_cls = (http.client.HTTPSConnection if url.scheme == "https"
                else http.client.HTTPConnection)
    conn = conn_cls(url.netloc, timeout=120)

    out = {}
    for name, value in headers:
        if name.lower() in HOP_BY_HOP or name.lower() == "host":
            continue
        out[name] = value
    out[HOST_HEADER] = host
    out["X-Tunnel-Authorization"] = "tunnel %s" % TUNNEL_TOKEN
    out["X-Tunnel-Skip-Anti-Phishing-Page"] = "true"

    conn.request(method, target, body=body or None, headers=out)
    return conn.getresponse()


def handle(sock, authority, base_context):
    peer_dst = original_destination(sock)
    try:
        tls = base_context.wrap_socket(sock, server_side=True)
    except (ssl.SSLError, OSError) as exc:
        log("handshake failed (original_dst=%s): %s" % (peer_dst, exc))
        sock.close()
        return

    host = tls.server_hostname
    try:
        if not host:
            log("no SNI (original_dst=%s), dropping" % peer_dst)
            return

        if TUNNEL_HOST and host.lower() == TUNNEL_HOST.lower():
            log("refusing tunnel-bound traffic for %s: the redirect exclusion missed an "
                "address, so this would loop back through the shim" % host)
            tls.sendall(b"HTTP/1.1 508 Loop Detected\r\nContent-Length: 0\r\n"
                        b"Connection: close\r\n\r\n")
            return

        stream = tls.makefile("rb")
        parsed = read_request(stream)
        if not parsed:
            return
        method, target, headers, body = parsed

        try:
            response = forward(method, target, headers, body, host)
        except OSError as exc:
            log("%s%s: tunnel failed: %s" % (host, target, exc))
            tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                        b"Connection: close\r\n\r\n")
            return

        payload = response.read()
        out = ["HTTP/1.1 %d %s" % (response.status, response.reason)]
        for name, value in response.getheaders():
            if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
                continue
            out.append("%s: %s" % (name, value))
        out.append("Content-Length: %d" % len(payload))
        out.append("Connection: close")
        tls.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + payload)
        log("%s %s%s -> %d" % (method, host, target, response.status))
    finally:
        try:
            tls.close()
        except OSError:
            pass


def main():
    preflight()
    authority = Authority(CERT_DIR)

    base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    base.load_cert_chain(authority.crt, authority.key)

    def sni(sock, name, _ctx):
        if name:
            try:
                sock.context = authority.context_for(name)
            except subprocess.CalledProcessError as exc:
                log("minting a certificate for %s failed: %s" % (name, exc))

    base.sni_callback = sni

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(64)
    log("listening on :%d, forwarding to %s" % (LISTEN_PORT, TUNNEL_URL))
    print("SHIM_READY", flush=True)

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client, authority, base),
                         daemon=True).start()


if __name__ == "__main__":
    main()
