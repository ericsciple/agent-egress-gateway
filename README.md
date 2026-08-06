# agent-gateway

Prototype credential gateway for an isolated agent step in an Actions workflow.

An agent running in a sandbox needs to call credentialed services. Handing it the
real secret means that anything which goes wrong with the agent goes wrong with
the secret. This gateway is the alternative: the agent holds a **placeholder**, and
the real credential is substituted on the way out, only on destinations you named.

- The agent can **use** the credential.
- The agent can never **read** it.
- The credential is only ever sent **where you said it works**.

Used by [`agent-microvm`](https://github.com/github/agent-microvm) and
[`agent-sandbox`](https://github.com/github/agent-sandbox). Not an Action itself.

## How it works

The gateway runs outside the guest, on the Actions runner. Guest traffic on `:443`
is redirected into it, it terminates TLS with a CA generated per run, and it
forwards the request to the real upstream.

```
guest ──:443──▶ gateway (runner) ──TLS──▶ upstream
              swaps placeholder→credential
```

A **lane** binds one placeholder to one real credential and the destinations where
that swap is allowed:

```json
[
  {
    "name": "sentry",
    "placeholder": "<random, generated per run>",
    "real": "<the real token>",
    "targets": [{ "host": "sentry.io", "path_prefix": "/api/0/projects/acme/" }]
  },
  {
    "name": "gitlab",
    "placeholder": "<random, generated per run>",
    "real": "<the real token>",
    "header": "Private-Token",
    "targets": [{ "host": "gitlab.com" }]
  }
]
```

The guest gets the placeholder in an environment variable and uses it exactly as it
would use the real token. Nothing else changes: an existing script keeps working.

## Rules it enforces

**The lane is matched on the same host we connect to.** Both come from the TLS
server name. A request whose `Host` header disagrees with the TLS name is refused
rather than reconciled, and a destination address supplied by the guest never
decides which socket we open. Without this, a caller could name a destination it is
authorised for and have the real credential delivered somewhere else.

**The swap happens in one header and nowhere else.** Only the lane's declared
header, defaulting to `Authorization`. Never another header, never the body.
Swapping more widely would let a caller put the placeholder in a field the upstream
stores, have the real credential substituted into it, and read it back out.

**The substitution preserves what the caller sent.** `Bearer <placeholder>` becomes
`Bearer <credential>`; a bare placeholder becomes a bare credential. The gateway
does not rebuild the header from a template, so no per-lane format configuration is
needed.

**A placeholder somewhere unexpected is ignored, not rejected.** It is a worthless
string. We only look at destinations we intend to swap on, so there is no scanning
of headers or bodies we otherwise have no reason to read.

**Reaching an allowed destination is not the same as asking for a credential.** The
swap only happens if the caller carries the placeholder, so a request that did not
ask to authenticate stays unauthenticated.

## Configuration

| Variable | Meaning |
|---|---|
| `GW_LANES` | JSON array of lanes. The real credentials live here and nowhere else. |
| `GW_EGRESS_ALLOW` | Comma-separated hosts reachable with no credential attached. |

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:8080` | Address to listen on. |
| `-mode` | `redirect` | How connections arrive. See below. |
| `-ca-out` | none | Write the CA certificate here, for the guest trust store. |
| `-lanes-env` | `GW_LANES` | Environment variable holding the lane JSON. |

`api.githubcopilot.com` is reserved and cannot be named by a lane, because that is
the inference lane's upstream and carries our own token. `api.github.com` is
deliberately **not** reserved: pointing a user-supplied token at the REST API is a
supported scenario wherever MCP has gaps.

### Modes

**`redirect`** — connections arrive from a netfilter `REDIRECT` rule, and the
original destination is recovered with `SO_ORIGINAL_DST` for logging.

```
iptables -t nat -A PREROUTING -i tap0 -p tcp --dport 443 -j REDIRECT --to-ports 8080   # agent-microvm
iptables -t nat -A OUTPUT           -p tcp --dport 443 -j REDIRECT --to-ports 8080     # agent-sandbox, in-guest
```

**`preamble`** — connections arrive over a relay that cannot preserve the original
destination, so the client sends one line naming it before the TLS stream starts.
The value is logged and never used for routing.

## Build

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent-gateway ./cmd/agent-gateway
```

One static binary, no runtime dependencies. It replaces a mitmproxy install plus a
CA-generation step that together cost about 16 seconds per run; generating the CA
in process takes about 0.15ms.
