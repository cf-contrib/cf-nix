# cf-nix-cache-api

> The Worker half of [cf-nix-cache](../..): a Nix binary cache on Cloudflare
> Workers and R2, written in Rust. It serves narinfo and NARs from R2, signs
> uploads, and authorizes uploaders by an OIDC token from an issuer you trust.

Reads are public. An upload needs an OIDC token as the password of HTTP Basic
credentials, from a provider in `CF_NIX_CACHE_API_OIDC_PROVIDERS`, for the cache's
audience, and matching one of that issuer's claim sets.

## Deploy

1. **Create the signing key** and store it in [Secrets Store](https://developers.cloudflare.com/secrets-store/), so it never passes through your deploy tooling. Wrangler prompts for the value: paste the whole `<key-name>:<base64>` line.
   ```sh
   nix key generate-secret --key-name cache.example.com-1
   wrangler secrets-store secret create <store-id> --name cf-nix-cache-signing-key --scopes workers --remote
   ```
   Clients need the matching public key in `trusted-public-keys` (`nix key convert-secret-to-public`).
2. **Decide who may upload**: a [provider list](#authentication). For GitHub Actions, look up numeric IDs to pin. Pin IDs, not names, because a deleted repo or org name can be re-registered by someone else:
   ```sh
   gh api orgs/<org> --jq .id           # repository_owner_id
   gh api repos/<org>/<repo> --jq .id   # repository_id
   ```
3. **Deploy** the released bundle with the [Terraform / OpenTofu module](../../deployment/terraform) (`//deployment/terraform?ref=<version>`). It downloads the release (`index.js` and `index_bg.wasm`, both required), creates the R2 bucket, and sets up the bindings below and the workers.dev URL (or an optional custom domain). To deploy a local build instead, run `worker-build --release` here and point the module's `bundle_dir` at this directory's `build/`.
4. **Check** that `<cache-url>/health/ready` returns `200`. An unbound bucket or an invalid provider list fails every request, this one too, as a `500` with the reason in Workers Logs. An unreadable signing key shows only on the first upload that needs signing, as a `500`.

`wrangler.toml` in this directory is for local development, not production.

## Bindings

| Binding | Type | Required | Description |
|---|---|---|---|
| `CF_NIX_CACHE_API_BUCKET` | R2 bucket | yes | Stores `.narinfo` and `.nar` objects. |
| `CF_NIX_CACHE_API_SECRET` | Secrets Store secret | conditional | `<key-name>:<base64>`, as emitted by `nix key generate-secret`. Required unless every uploader sends signed narinfo. Only a Secrets Store binding is taken: bound as a plain secret or var, the Worker refuses to start, so the key never passes through Terraform or a command line. |
| `CF_NIX_CACHE_API_OIDC_PROVIDERS` | var | for uploads | JSON array of the identity providers whose tokens may upload; see [Authentication](#authentication). Unset, uploads are off. |

## Authentication

`CF_NIX_CACHE_API_OIDC_PROVIDERS` lists the identity providers whose tokens may
upload: each one's issuer, the audience its tokens must be for, and who may
upload:

```json
[
  {
    "issuer": "https://token.actions.githubusercontent.com",
    "audience": "https://cache.example.com",
    "claims": [
      { "repository_owner_id": "100000001", "repository_id": "200000002", "ref": "refs/heads/main" },
      { "repository_owner_id": "100000001", "repository": "example-org/*", "environment": "release" }
    ]
  },
  {
    "issuer": "https://example.cloudflareaccess.com",
    "audience": "<the Access application's AUD tag>",
    "jwks_uri": "https://example.cloudflareaccess.com/cdn-cgi/access/certs",
    "claims": [{ "email": "uploader@example.com" }]
  }
]
```

| Field | |
|---|---|
| `issuer` | Matched exactly against the token's `iss`. HTTPS, or plain HTTP on a loopback address for local development. |
| `audience` | Must be one of the token's `aud` values (a trailing `/` is ignored on either side). Use one only this cache accepts, such as its URL, so a token meant for another service can't be replayed here. |
| `jwks_uri` | Optional. Where the issuer's signing keys are. Without it, they're taken from the issuer's discovery document, `<issuer>/.well-known/openid-configuration`, which must name the same issuer. |
| `claims` | The claim sets. A token is accepted if any one matches. |

A token is checked in this order, and the first failure is what the uploader
sees:

1. Its `iss` must be a configured issuer (`401 issuer … is not configured`).
2. Its signature must verify with that issuer's keys, never with keys from
   anything in the token. Only RS256 is accepted.
3. Its `aud` must include the issuer's `audience`
   (`401 token audience is …, expected …`), and its `exp` and `nbf` must hold,
   within a minute of clock skew (`401 token expired`).
4. One of the issuer's claim sets must match (`403 … no claim set for … matched`).
   The message doesn't say which claims would have, since that's the policy.

**Claim sets.** Within a set every claim must match. A pattern is exact, or a
prefix ending in a single `*` (`example-org/*`, `refs/heads/release/*`); a `*`
anywhere else is refused. `*_id` claims must match exactly. A claim missing
from the token never matches, a list claim (`groups`) matches if any entry
does, and numbers and booleans compare as written (`"email_verified": "true"`).

> [!WARNING]
> **Pin your tenant.** Some issuers give a token for any audience to anyone's
> projects: GitHub Actions to every repository on github.com, GitLab.com and
> Terraform Cloud likewise. For one of those, put your tenant's ID in every claim
> set (`repository_owner_id` for GitHub Actions, `namespace_id` or `project_id`
> for GitLab, `terraform_organization_id` for Terraform Cloud), or any project on
> the issuer can upload. The Worker doesn't know which issuers these are: the
> claim sets are the whole policy. Issuers that only give tokens to people who
> passed your policy, like Cloudflare Access or a cf-oidc-auth broker, need no
> pin.

The config is checked when an upload reads it. An invalid one fails closed:
the upload gets `500`, and the reason is logged. Every upload
is logged with the identity it resolved to: the token's subject and issuer, and
the claim set that let it in.

### Sending the token

Nix sends credentials to a binary cache only from a netrc file (`netrc-file` in
`nix.conf`, or `--option netrc-file`), so the token goes there, as the
password. The login isn't read:

```
machine cache.example.com
  login oidc
  password <the token>
```

The root README has a [workflow step](../../README.md#quick-start) for GitHub
Actions. Its token lasts 5 minutes, so the upload has to finish within that.
Nix reads the netrc again for every request, so for a longer one, rewrite the
file with a fresh token while `nix copy` runs. Keep the file readable only by
you (`chmod 600`).

### People: your GitHub token, through cf-oidc-auth

The cache never takes a GitHub user token itself: it isn't signed, so only
GitHub could vouch for it. A [cf-oidc-auth](https://github.com/cf-contrib/cf-oidc-auth)
broker can, and exchanges it for a token of its own for the cache. Trust the
broker as one more provider, pinned to the profile that issues for the cache:

```json
{
  "issuer": "https://cf-oidc-broker.example.com",
  "audience": "https://cache.example.com",
  "claims": [{ "profile": "nix-push-people" }]
}
```

The broker's profile decides who may upload, for example anyone with `write`
on a repo (see its [Tokens for other services](https://github.com/cf-contrib/cf-oidc-auth/tree/main/packages/cf-oidc-broker#tokens-for-other-services)).
A person then exchanges `gh auth token` once and uploads. The broker's token
lasts as long as the profile's `max_ttl` (1 hour unless it sets more), so there's
nothing to refresh; run it again once it has expired.

```sh
token=$(curl -fsS https://cf-oidc-broker.example.com/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$(gh auth token)" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=https://cache.example.com \
  -d repository=example-org/nix-cache-access \
  -d profile=nix-push-people | jq -er .access_token)
(umask 077 && printf 'machine cache.example.com\n  login oidc\n  password %s\n' "$token" > ~/.netrc-nix-cache)
nix copy --to 'https://cache.example.com?compression=none' --option netrc-file ~/.netrc-nix-cache ./result
```

The cache only ever sees the broker's short-lived token, never the GitHub one.

## HTTP API

The API is specified by the SDK's [OpenAPI document](../cf-nix-cache-sdk/openapi/nix/cache/v1/cachev1.yaml).
The Worker implements the server [generated from it](../cf-nix-cache-sdk), so
requests are checked against the document before a handler sees them. Uploads
must use the content type Nix sends: `text/x-nix-narinfo` for narinfo and
`application/x-nix-nar` for NARs.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/nix-cache-info` | public | Cache metadata (priority, etc.). |
| `GET` | `/<hash>.narinfo` | public | Narinfo for a store path. |
| `HEAD` | `/<hash>.narinfo` | public | Existence check for a narinfo (200 / 404). |
| `PUT` | `/<hash>.narinfo` | token | Upload a narinfo. |
| `POST` | `/` | public | Mass query: a newline-separated list of hashes in, the cached subset out. |
| `GET` | `/nar/<hash>.nar` | public | NAR archive bytes. |
| `HEAD` | `/nar/<hash>.nar` | public | Existence check for a NAR (200 / 404). |
| `PUT` | `/nar/<hash>.nar` | token | Upload a NAR archive. |
| `GET` | `/health/live`, `/health/ready` | public | `200` while the Worker is up and serving, and `500`, like every request, while its bucket is unbound or its provider list invalid. The SDK's `HealthHandler`; a deployment check, so not in the OpenAPI document. |

**Errors** are JSON, in the shape cf-oidc-auth uses: `{ "error": "<code>", "message": "<reason>" }`. Nix prints the body of a failed upload, so the message says what to fix, except for `500` and `502`, whose details go only to the logs.

| Status | `error` | Means |
|---|---|---|
| `400` | `bad_request` | The narinfo or request is invalid, e.g. `narinfo is missing NarSize` |
| `401` | `unauthorized` | No token, or one that's malformed, badly signed, expired, for another audience, or from an issuer that isn't configured; or uploads are off |
| `403` | `forbidden` | A valid token that no claim set for its issuer allows |
| `404` | `not_found` | No such narinfo or NAR |
| `500` | `misconfigured` | The provider list, the bindings or the signing key are invalid |
| `500` | `internal_error` | A stored object is unreadable |
| `502` | `upstream_error` | The token's issuer, its discovery document or its keys, couldn't be reached |

A request the document doesn't allow is rejected before it reaches the Worker,
as `application/problem+json` with a `code`: `415` for an undeclared content
type, `413` for a body over 64 MiB, `400` or `422` for a malformed request.

**Validation and signing:** the Worker parses each uploaded narinfo, checks its
format, and requires its `StorePath` to match the request's hash. Every stored
narinfo carries a `Sig:`. If the uploader didn't sign and `CF_NIX_CACHE_API_SECRET`
is set, the Worker signs the upload itself. Otherwise the `PUT` returns `400`.

## Security

- **No shared upload secret.** Uploaders send short-lived tokens issued for
  this cache. The only long-lived secret is the narinfo signing key, in
  Secrets Store, so it never passes through Terraform or CI.
- **Keys come from the configured issuer only.** A token picks its issuer by
  `iss`, but its keys are fetched from that issuer's discovery document or
  configured `jwks_uri`, never from a URL in the token. The discovery document
  must name the issuer it's for.
- **Guardrails**, checked when the config loads: every issuer needs claim
  sets, a `*` may only end a pattern, and `*_id` claims match exactly. Pinning
  the tenant of an issuer that serves anyone's projects is up to the claim
  sets; see [Authentication](#authentication).
- **Tokens are never stored or logged.** Auth results are cached per isolate,
  keyed by the SHA-256 of the token. Logs show the resolved identity.
- **Issuers' keys** are cached for an hour, and an unknown `kid` refetches
  them at most once a minute per issuer, so made-up tokens can't make the
  Worker hammer an issuer.
- **Signatures** are verified with WebCrypto (RS256), so no RSA crate ships in
  the bundle.

## Limitations

- A token can't be revoked: it's good until it expires. Issuers keep that
  short (GitHub Actions: 5 minutes).
- Only RS256 tokens are accepted, which is what GitHub Actions, Cloudflare
  Access and most issuers sign with.
- Compressed NARs (`.nar.xz` etc.) aren't supported: uploads must use
  `?compression=none`.
- NARs are held in memory on the way in and out, and an upload can be at most
  64 MiB (`413`). A Worker has 128 MB of memory.
- Secrets Store is in open beta.

## Development

The crate is a member of the Cargo workspace at the repo root. It builds the
SDK, which generates the API from its OpenAPI document, so a change to the
document shows up as a compile error here. Run everything inside the dev shell:

```bash
nix develop -c cargo test           # unit tests, from the repo root
nix develop -c worker-build --dev   # build the bundle into ./build (this directory)
nix develop -c wrangler dev         # serve locally (this directory)
```

To sign uploads locally, put a signing key in the local Secrets Store that
`wrangler.toml` binds; Wrangler prompts for the value, so it stays off the
command line. Without one, only narinfo the uploader signed can be stored.

```bash
nix key generate-secret --key-name local-dev   # a throwaway key: copy the line it prints
nix develop -c wrangler secrets-store secret create 00000000000000000000000000000000 --name signing-key --scopes workers   # paste it when prompted
```

The integration tests call the Worker under `wrangler dev` through the SDK's
client. They run their own OIDC issuer on `127.0.0.1:8788`, the one
`wrangler.toml` trusts, and upload with tokens it signs, so they need no
credentials. `tests/run.sh` starts a `wrangler dev` of their own, on port 8789
with its own local storage and a throwaway signing key, runs them, and stops
it, so one you're running is left alone. CI runs it too:

```bash
nix develop -c tests/run.sh                                  # this directory
```

To run them against a `wrangler dev` you've started instead, set
`CF_NIX_CACHE_API_URL` if it isn't on `http://127.0.0.1:8787`, and its
`CF_NIX_CACHE_API_OIDC_PROVIDERS` audience to match:

```bash
nix develop -c cargo test --features integration
```

## Dependencies

- [`cf-nix-cache-sdk`](../cf-nix-cache-sdk), the API's types, the server traits the Worker implements, and the narinfo format: parsing, validation and signing
- [`worker`](https://crates.io/crates/worker) and [`worker-macros`](https://crates.io/crates/worker-macros), the Cloudflare Workers Rust SDK, with [`axum`](https://crates.io/crates/axum), which serves the SDK's router
- [`http-auth-basic`](https://crates.io/crates/http-auth-basic) for the auth header
- [`serde`](https://crates.io/crates/serde) and [`serde_json`](https://crates.io/crates/serde_json) for the provider list, token claims, discovery documents and key sets
- [`web-sys`](https://crates.io/crates/web-sys) for WebCrypto, which verifies token signatures
- [`base64`](https://crates.io/crates/base64) to decode tokens, and [`sha2`](https://crates.io/crates/sha2) to key the auth cache by the token's hash
