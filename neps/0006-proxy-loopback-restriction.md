---
nep: 0006
title: Opt-in loopback restriction for the network proxy
authors:
  - blakepettersson
status: draft
created: 2026-10-01
superseded-by:
---

# NEP-0006: Opt-in loopback restriction for the network proxy

## Summary

Add `network.block_loopback` and `network.loopback_allow` profile fields. When
set, the nono proxy refuses to connect to loopback destinations except
configured credential-route upstreams (dialled by the proxy itself) and
explicitly listed ports. This closes a bypass where a sandboxed process uses
the proxy to reach a local service directly, skipping the credential route
that is supposed to mediate it.

## Motivation

When the proxy is active, the OS sandbox runs the child in
`NetworkMode::ProxyOnly { port }`: the only TCP the child can open is to the
proxy's loopback port. This holds on both platforms and is enforced by the
kernel.

The gap is one layer up. With `network.block: false` the proxy filter is
`ProxyFilter::allow_all()`, and `HostFilter` denies only link-local
destinations. It has no notion of loopback. The child cannot reach a local
service directly, but it can ask the proxy to (#605).

This matters whenever a credential route fronts a service on `localhost`.
Reproduced on k3d (API server on `0.0.0.0:<port>`, `kubectl proxy` on
`127.0.0.1:8001`, and a route whose `endpoint_policy` denies `secrets`):

| Attempt | Result today |
|---|---|
| `GET …/secrets` through the route | `403`: policy enforced |
| The same request addressed to `127.0.0.1:8001` through the proxy | `200`, real Secret objects |
| `CONNECT 0.0.0.0:<port>` / `127.0.0.1:<port>` | tunnel established |
| Direct socket, bypassing the proxy | blocked by `ProxyOnly` |

The route's `endpoint_policy`, `endpoint_rules`, credential injection and audit
can all be skipped by addressing the upstream directly. The same applies to
Kind, minikube, local databases, and any other service on loopback.

### Goals

- Let a profile stop the proxy from reaching loopback, so a credential route
  is the only path to a local service.
- Keep credential routes to loopback upstreams working.
- Match on the destination, not its spelling, including names that resolve
  onto loopback (DNS rebinding, `/etc/hosts`).
- Fail closed when the setting cannot be enforced.
- Behave identically on Linux and macOS.

### Non-Goals

- Changing the default. Loopback stays reachable through the proxy unless a
  profile opts in (see Open Questions).
- Private (RFC 1918), ULA, CGNAT, or host-interface ("hairpin") ranges, and
  port-scoped allow entries. These are requested in #1994 and could build on
  the same mechanism, but they are out of scope here.
- `--open-port` / `allow_connect_port`. Those grant the child direct,
  kernel-level localhost TCP that never passes through the proxy.
- Any change to OS-level (Landlock/Seatbelt) rules.

## Proposal

### Profile surface (`nono-cli`)

```json
{
  "network": {
    "block_loopback": true,
    "loopback_allow": [8080]
  }
}
```

- `block_loopback` (bool, default `false`): the proxy refuses loopback
  destinations with `403`. It is independent of `network.block`: it governs
  what the proxy will reach, not whether outbound is permitted, and it does
  not enable strict host filtering.
- `loopback_allow` (list of ports 1–65535, default empty): loopback ports that
  stay reachable. Has no effect unless `block_loopback` is true.
- Under `extends`, `block_loopback` is OR-ed (a child cannot turn off a
  base's restriction) and `loopback_allow` lists are concatenated and
  deduplicated.

### What counts as loopback

A destination is loopback if its literal or **any** of its resolved addresses
is:

- `127.0.0.0/8` or `::1`;
- the unspecified address `0.0.0.0` or `::`, because `connect(2)` to it
  reaches localhost;
- an IPv4-mapped IPv6 form of either: all of `::ffff:127.0.0.0/104`, and
  `::ffff:0.0.0.0`.

Or if the hostname is `localhost` or ends in `.localhost` (RFC 6761). This is
matched after normalising case, the trailing dot, and Unicode label
separators.

The proxy dials the addresses it checked (`CheckResult::resolved_addrs`), so a
DNS answer that changes between check and connect cannot reach loopback.

### Through an upstream proxy

With `upstream_proxy`, the proxy does not dial the destination itself. It
sends `CONNECT <host>:<port>` to the enterprise proxy, which resolves the name
again. That second answer can differ from the one checked locally. If the
enterprise proxy runs on the same machine, as many endpoint agents do, a
rebound answer reaches local loopback.

Under `block_loopback`, every request a client sends through the upstream
proxy (the CONNECT tunnel and plain-HTTP forwarding) names the **first
checked IP** instead of the hostname, bracketed for IPv6. If the name does not
resolve locally, there is nothing safe to pin to, so the request is refused
with `502` before anything is sent upstream. Forwarding the hostname would
skip the loopback check entirely.

Without `block_loopback`, the hostname is forwarded as today.

Pinning changes what the enterprise proxy sees: an IP instead of a name. A
proxy that filters by domain may then refuse the request. That is a
fail-closed outcome, but it can make the two settings impractical together
with such a proxy (see Open Questions).

Route-scoped dials through the upstream proxy (reverse-proxy routes and
TLS-intercepted routes) are outside the loopback policy (see below), so they
are not pinned.

### Evaluation order

The loopback check runs **before** the host allowlist. `allow_domain: ["*"]`,
a broad `network_profile`, or an allowlisted name that resolves to `127.0.0.1`
cannot override it.

### Credential-route exemption follows the caller, not the address

A credential route to a loopback upstream (e.g. `https://localhost:6443`) must
keep working. The exemption is tied to **who is dialling**: when the proxy
dials a route's upstream, after the route's endpoint policy and credential
injection have run, the check is bypassed (`check_route_upstream`).

Routes can be reached two ways, and both stay mediated:

- **Reverse proxy:** the client sends a request to the route's prefix on the
  proxy, and the proxy dials the upstream.
- **TLS intercept:** a client `CONNECT` to a route upstream that needs L7
  visibility is accepted and terminated locally. Each inner request then
  passes the route's policy before the proxy dials the upstream.

What is refused is an **unmediated** path to that address: a CONNECT tunnel
that relays raw bytes to the upstream, or a plain-HTTP forward to it. Both are
checked with the loopback policy applied.

Exempting by address would reopen the bypass. If `localhost:6443` were
allowlisted because a route uses it, a client could address it directly and
skip the route.

### Fail closed without a proxy

`block_loopback` is enforced by the proxy. If a profile sets it but nothing
starts the proxy, there is no proxy to enforce it, and the child would get
unrestricted loopback. That configuration is rejected at launch with an error
that names the cause and points to `network.block` as the alternative.

"Starts the proxy" uses the same condition as the rest of the launch path
(`ProxyLaunchOptions::is_active`) rather than a separate list. Today that is
any of `network_profile`, `allow_domain`, `deny_domain`, endpoint rules,
`credentials`, credential routes, or `upstream_proxy`.

### Library surface (`nono`)

None. The decision type lives in `nono-proxy`:

```rust
pub enum ProxyFilterResult {
    Host(nono::net_filter::FilterResult),
    DenyLoopback { destination: String },
}
```

The proxy's own check result (`CheckResult::result`) is this type. Callers
only use `is_allowed()` and `reason()`, so call sites don't change. The
library's public `FilterResult` stays as it is: no new variant and no API
break. The policy itself (`LoopbackPolicy`) also lives in `nono-proxy` and is
configured by `nono-cli`.

### Platforms

Enforcement is entirely in the proxy (userspace), so it behaves the same on
Linux and macOS. No Landlock or Seatbelt rules change. The OS layer continues
to provide `ProxyOnly`, which is what makes the proxy the only route off the
child's loopback interface.

### Backward compatibility

Additive and off by default. Existing profiles behave exactly as before. The
schema gains two optional fields. The `nono` library API is unchanged.

Within `nono-proxy`, `CheckResult::result` changes from the library's
`FilterResult` to `ProxyFilterResult`. `nono-proxy` is a workspace crate, and
every consumer in this repository is updated in the same change.

## Security Considerations

- **Least privilege:** this only removes reach. With the setting on, the
  child can do strictly less than before. The only things it can still reach
  on loopback are the profile's own credential routes (through their policy)
  and ports the profile lists explicitly.
- **Fail-secure:** without a proxy, `block_loopback` is a launch error rather
  than being silently ignored. A failed DNS lookup yields no addresses, and
  the proxy then refuses to connect (`502`) rather than re-resolving.
  Through an upstream proxy, a target with no checked address is refused
  rather than forwarded by name. Every resolved address is checked, so one
  loopback address among several answers is enough to deny.
- **Path handling:** not applicable; no filesystem paths are involved.
- **Library/CLI boundary:** unchanged. The `nono` library gains nothing. The
  mechanism and its result type live in `nono-proxy`, and the policy (whether
  to restrict, which ports to exempt) is set by `nono-cli`.
- **Credentials:** no new credential handling. The change *protects*
  credential routes by making them non-bypassable. Denial messages contain
  only the sanitised `host:port`.
- **Residual exposure:**
  - `--open-port` still grants direct loopback TCP. This is documented, and
    the two are not combined implicitly.
  - Non-loopback private addresses (#1994) are unaffected.
  - NAT64 (`64:ff9b::/96`) embeddings of loopback are not yet matched.
  - The existing link-local (cloud metadata) floor has the same
    upstream-proxy re-resolution gap described above. Pinning is applied only
    under `block_loopback` here. Extending it to the link-local floor changes
    behaviour for every upstream-proxy user, so it should be a separate
    change.

## Alternatives Considered

- **Allow the proxy port when `block: true`** (#605, option 1), or **scoped
  `block_loopback` at the OS layer** (option 3). Under `ProxyOnly` the OS
  layer already allows only the proxy port. The leak is in what the proxy
  does on the child's behalf, so it must be closed there.
- **OS-level loopback deny with general egress allowed.** Landlock is
  strictly allow-list and cannot express deny-within-allow. It would be
  enforced on macOS and silently not on Linux.
- **Address-based exemption for route upstreams.** Reopens the bypass (see
  above).
- **A `DenyLoopback` variant on the library's `FilterResult`.** An earlier
  draft of this NEP proposed it. It breaks downstream exhaustive `match`es,
  because the enum is not `#[non_exhaustive]`, and puts a proxy-only decision
  in the policy-free library. Adding `#[non_exhaustive]` would fix the first
  problem but not the second.
- **Reject `block_loopback` with `upstream_proxy` at launch.** Simpler, and
  avoids pinning, but blocks a legitimate setup. It remains the fallback if
  pinning proves impractical (see Open Questions).
- **Default on.** Reverses current behaviour, where the proxy reaches loopback
  unless told otherwise, and would break existing setups that proxy to local
  dev servers. Left as an open question.

## Open Questions

- **Upstream proxies that filter by domain:** pinning the CONNECT target to an
  IP may be refused by an enterprise proxy that allowlists names. Is that
  acceptable as the fail-closed outcome, or should `block_loopback` plus
  `upstream_proxy` be rejected at launch instead, so the conflict is reported
  up front?
- **Default:** should loopback restriction become the default at 1.0.0? It
  would reach parity with the link-local floor and with #1994's request 1.
- **Generalisation:** should this become a destination-class policy (loopback
  now, private/ULA/CGNAT/host-interface later, per #1994), with
  `block_loopback` as the first class? If so, the field names should be
  settled before they ship.
- **`loopback_allow` under `extends`:** a child profile cannot turn off a
  base's `block_loopback`, but it can add `loopback_allow` ports, which
  re-opens loopback reach the base restricted. This matches how
  `open_port`, `connect_port` and the other `network` port lists merge
  (concatenate and deduplicate). Is it acceptable, or should a child be unable to
  widen a base's loopback exemptions?
- **NAT64:** include `64:ff9b::/96` with embedded loopback in this change?
- **`--open-port` with `block_loopback`:** warn, error, or leave as
  documented?

## Reference implementation

A working implementation, with unit tests and integration tests in
`crates/nono-proxy/tests/loopback_restriction.rs`, is available at
[blakepettersson/nono@feat/proxy-block-loopback](https://github.com/blakepettersson/nono/tree/feat/proxy-block-loopback).
It will be opened as a PR only after this NEP is accepted.
