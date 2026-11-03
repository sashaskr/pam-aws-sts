# Design note: how credentials reach the server

**Status:** open question, no code change proposed yet
**Audience:** anyone deciding whether to deploy `pam_aws_sts`, and anyone
planning its next major version

This note exists because the current authentication model has a property that
is easy to miss when reading the README, and that property is the single
largest security consideration in the project. Nothing here is a bug report.
The module does what it says. The question is whether what it says is the
right design.

## What happens today

The client puts a full set of STS credentials in the PostgreSQL password field:

```json
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","SessionToken":"...","Expiration":"..."}
```

PostgreSQL passes that to PAM, the module parses it, signs a
`GetCallerIdentity` call with it, and uses the response to decide whether the
connection is allowed.

The consequence: **the database server receives, and briefly holds in process
memory, a credential that works against every AWS API the IAM principal can
reach.** Not a token scoped to "prove who I am". The actual secret.

## Why that matters

The module only ever calls `sts:GetCallerIdentity`. But the credential it
receives is not limited to that. For the remaining lifetime of the session,
which can be up to 12 hours, whoever holds it can call S3, KMS, IAM, EC2, or
anything else the role permits.

So the database host becomes a place where AWS credentials accumulate. The
ways they leak out are ordinary operational events, not exotic attacks:

- A core dump from a crashed backend. Relevant here: a panic inside the PAM
  module aborts the backend, and the module runs inside the backend process.
- Process memory read by anything running as the `postgres` user, or as root.
- Swap, hibernation images, VM snapshots, or a hypervisor-level backup.
- `PGPASSWORD` on the client side, which is visible in `/proc/<pid>/environ`
  to other processes of the same user and frequently lands in shell history.
- Any future code path in this module that logs or formats the credential
  struct. The review that prompted this note found the derived `Debug` impl
  renders the secret key in full.

None of these require the server to be malicious. They require the server to
be a normal, imperfect computer.

### The IAM Roles Anywhere case makes it sharper

The README specifically recommends IAM Roles Anywhere with a YubiKey for
regulated environments, and says:

> This binds authentication to a physical hardware token — credentials cannot
> be extracted or copied.

That is true of the *certificate* in the token. It is not true of the STS
session credentials the signing helper exchanges it for. Those are ordinary
bytes, and the current design sends them to the database. The hardware binding
protects the first hop and is then given up at the second. Anyone choosing
this module for PCI-DSS, SOC 2, or FedRAMP reasons should understand that
tradeoff explicitly rather than inferring the stronger claim.

## The alternative: send a signed request, not the secret

`sts:GetCallerIdentity` has an unusual property that makes it well suited to
being used as a proof of identity. Per the
[STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html),
no permissions are required to call it, and an explicit `Deny` cannot block
it, because the same information is returned either way.

That means a *signed request* to `GetCallerIdentity` is a near-ideal bearer
token. It proves which principal produced it, and it authorizes nothing else.

The flow would become:

1. Client signs a `GetCallerIdentity` request with SigV4, locally. The secret
   never leaves the client.
2. Client sends only the signed request (headers plus body, or a presigned
   URL) as the PostgreSQL password.
3. Module replays it to the real STS endpoint and reads the identity from the
   response.
4. Account and role checks proceed exactly as they do now.

This is the same shape as the token Kubernetes uses for IAM-based cluster
authentication, where the API server likewise never sees the caller's secret.

### Comparison

| | Today: raw credentials | Proposed: signed request |
|---|---|---|
| What the server receives | `SecretAccessKey` + `SessionToken` | A signature over one STS call |
| What the server can do with it | Anything the role permits, for hours | Learn the caller's identity |
| Value of a server-side memory leak | Full AWS credentials | An identity assertion, expiring in minutes |
| Replay window | Session lifetime, up to 12h | Bounded by the signature's `X-Amz-Date` |
| Client-side change | none | must sign before connecting |
| Server-side verification | SigV4 signing in the module | signature verification delegated to STS |

The last row is worth noting: the module would do *less* cryptographic work,
not more. It stops holding a signing key and becomes a relay.

## Costs and open questions

This is not free, and the questions below should be answered before anyone
writes code.

1. **Client ergonomics.** Today a client can pipe `aws sts assume-role` output
   straight into `PGPASSWORD`. Signing a request first needs a helper binary
   or a small script. Does the project ship one? For which platforms?
2. **Password size.** A signed request with headers is larger than the
   credential JSON. PostgreSQL removed its arbitrary password length limit in
   version 14, so this is probably fine, but it needs measuring against the
   oldest supported server.
3. **Replay.** A signed request is replayable by anyone who intercepts it,
   until it expires. That is a smaller window than today and the replay only
   yields an identity assertion rather than credentials, but it is not zero.
   Does the module need a nonce cache? That reintroduces state into what is
   currently a stateless check.
4. **Which encoding.** A presigned URL is compact and easy to document. A
   serialized header set is more faithful to what SigV4 produces. Pick one and
   version it, so the format can change later.
5. **Migration.** Raw-credential mode cannot be removed in a patch release.
   The likely shape is a config flag that accepts both, defaults to both for
   one minor version, then defaults to signed-only.
6. **Does the threat model justify it?** If the database and the IAM
   principals are in the same trust domain and the same blast radius, the
   current design may be acceptable. The case for changing is strongest for
   exactly the regulated, hardware-token deployments the README targets.

## Recommendation

Treat the current model as acceptable only when the database host is trusted
to the same level as the IAM principals that log into it, and document that
assumption prominently. For the hardware-token deployments the README
promotes, the current model undercuts the property users think they are
buying.

Prototype the signed-request path behind a config flag and measure the
ergonomic cost before committing to it. The security argument is strong; the
adoption cost is the real unknown.

Until then, the mitigations that do not require a redesign:

- Require TLS on the client connection so the credential is at least not
  exposed in transit.
- Keep the IAM role scoped to the minimum set of permissions it needs, so a
  harvested credential is worth less.
- Keep session lifetimes short.
- Disable core dumps for the PostgreSQL service
  (`ulimit -c 0`, or `Storage=none` in `coredump.conf`).
- Prefer a client-side credential helper over exporting `PGPASSWORD`.
