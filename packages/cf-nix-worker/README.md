# cf-nix-cache Worker

> The Worker half of [cf-nix-cache](../..): a Nix binary cache on Cloudflare
> Workers and R2, written in Rust. It serves narinfo and NARs from R2, signs
> uploads, and authorizes uploaders by their GitHub identity.

Reads are public. Uploads need HTTP Basic credentials, and the username picks
how the Worker checks the password: `github` for a person's GitHub token, `oidc`
for a GitHub Actions OIDC token.

## Deploy

Use the [Terraform / OpenTofu module](terraform). It deploys the released
bundle (`index.js` and `index_bg.wasm`, both required, because `index.js`
imports `./index_bg.wasm`), creates the R2 bucket, and sets the bindings below.

`wrangler.toml` in this directory is for local development, not production.

## Bindings

| Binding | Type | Required | Description |
|---|---|---|---|
| `CF_NIX_WORKER_BUCKET` | R2 bucket | yes | Stores `.narinfo` and `.nar` objects. |
| `CF_NIX_WORKER_SECRET` | Secrets Store secret | conditional | `<key-name>:<base64>`, as emitted by `nix key generate-secret`. Required unless every uploader sends signed narinfo. A plain secret or var also works, e.g. for `wrangler dev`. |
| `CF_NIX_WORKER_GITHUB_REPOSITORY` | var | for `github` | `owner/repo`. Users with push access to it can upload. |
| `CF_NIX_WORKER_GITHUB_OWNER_ID` | var | for `oidc` | Numeric ID of the GitHub org or user whose repos may upload (`gh api orgs/<org> --jq .id`, or `users/<user>`). |
| `CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE` | var | for `oidc` | Expected `aud` of the OIDC token, e.g. the cache URL. Can't be GitHub's default. |
| `CF_NIX_WORKER_GITHUB_OIDC_RULES` | var | for `oidc` | JSON array of claim rules; see [CI: GitHub Actions OIDC](#ci-github-actions-oidc). |

## Authentication

| Username | Password | The Worker checks | Enabled by |
|---|---|---|---|
| `github` | A GitHub user token (`gh auth token`) | The user has push access to `CF_NIX_WORKER_GITHUB_REPOSITORY` | `CF_NIX_WORKER_GITHUB_REPOSITORY` |
| `oidc` | A GitHub Actions OIDC token | Signature, issuer, audience, expiry and owner, then `CF_NIX_WORKER_GITHUB_OIDC_RULES` | `CF_NIX_WORKER_GITHUB_OWNER_ID`, `CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE`, `CF_NIX_WORKER_GITHUB_OIDC_RULES` |

A mechanism is off unless its bindings are set. With none set, every upload
gets `401`. An invalid configuration, such as only some of the OIDC bindings,
fails closed: uploads get `500` and the reason is logged.

Every upload is logged with the identity it resolved to. To check your
credentials before a long `nix copy`:

```bash
curl --netrc-file ~/.netrc https://<your-worker>.workers.dev/auth/whoami
# {"kind":"github","subject":"octocat"}
```

Nix sends credentials to a binary cache only from a netrc file (`netrc-file` in
`nix.conf`) or the URL, so that's where they go.

### People: GitHub token

Anyone with push access to `CF_NIX_WORKER_GITHUB_REPOSITORY` can upload with
their own GitHub token. To manage access by team, give the team write access to
that repo.

Put your token in a netrc file readable only by you (`chmod 600 ~/.netrc`):

```
machine <your-worker>.workers.dev
  login github
  password <output of gh auth token>
```

and point Nix at it with `netrc-file = /home/you/.netrc` in `nix.conf`.

`gh auth token` usually has `repo` scope on every repo you can reach and never
expires. For a narrower credential, use a
[fine-grained token](https://github.com/settings/personal-access-tokens/new)
limited to `CF_NIX_WORKER_GITHUB_REPOSITORY`, with an expiry.
[gh-nix](https://github.com/gh-extensions/gh-nix) (planned,
[gh-extensions/gh-nix#1](https://github.com/gh-extensions/gh-nix/issues/1))
will avoid the plain-text file altogether.

The Worker checks the token with the GitHub API and reuses the result for 5
minutes, keyed by a hash of the token. Removing someone's push access takes
effect within those 5 minutes.

GitHub App installation tokens (`ghs_…`, including `GITHUB_TOKEN` in Actions)
are rejected. They identify a repo rather than a person, can't be limited to a
branch, and fork pull requests get one too. Use OIDC in CI.

### CI: GitHub Actions OIDC

`CF_NIX_WORKER_GITHUB_OIDC_RULES` is a JSON array of rules, and a token is
accepted if any rule matches. Within a rule every claim must match. `*` matches
any run of characters, including `/`, except in `*_id` claims, which must match
exactly. A claim missing from the token never matches.

```json
[
  { "repository_id": "200000002", "ref": "refs/heads/main" },
  { "repository": "example-org/*", "environment": "release" }
]
```

Every token must also come from a repo owned by `CF_NIX_WORKER_GITHUB_OWNER_ID`,
because GitHub issues OIDC tokens to every repository on github.com. The token's
audience must equal `CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE` (a trailing `/` is
ignored). The audience can't be GitHub's default `https://github.com/<owner>`,
so a token requested for AWS or GCP doesn't work here.

In a workflow, the [action](../cf-nix-action) sets this up: it gets the job's
OIDC token, checks it against `/auth/whoami`, points Nix at a netrc file holding
it, and refreshes it every 4 minutes. GitHub OIDC tokens expire after 5 minutes,
and Nix reads the netrc again for every request, so long uploads keep working.

## HTTP API

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/nix-cache-info` | public | Cache metadata (priority, etc.). |
| `GET` | `/<hash>.narinfo` | public | Narinfo for a store path. |
| `HEAD` | `/<hash>.narinfo` | public | Existence check for a narinfo (200 / 404). |
| `PUT` | `/<hash>.narinfo` | basic | Upload a narinfo. |
| `POST` | `/` | public | Mass query: a newline-separated list of hashes in, the cached subset out. |
| `GET` | `/nar/<hash>.nar` | public | NAR archive bytes. |
| `HEAD` | `/nar/<hash>.nar` | public | Existence check for a NAR (200 / 404). |
| `PUT` | `/nar/<hash>.nar` | basic | Upload a NAR archive. |
| `GET` | `/auth/whoami` | basic | `{ kind, subject, rule? }`: the identity the credentials resolve to. |

**Errors:** `401` means missing or invalid credentials, `403` valid credentials
without upload access, `500` an invalid auth configuration, and `502` that the
GitHub API or GitHub's signing keys couldn't be reached.

**Validation and signing:** the Worker parses each uploaded narinfo, checks its
format, and requires its `StorePath` to match the request's hash. Every stored
narinfo carries a `Sig:`. If the uploader didn't sign and `CF_NIX_WORKER_SECRET`
is set, the Worker signs the upload itself. Otherwise the `PUT` returns `400`.

## Security

- **No shared upload secret.** The only long-lived secret is the narinfo
  signing key, in Secrets Store, so it never passes through Terraform or CI.
- **OIDC guardrails**, checked when the config loads: the owner pin and a
  custom audience are required, and `*_id` claims can't be globbed.
- **Tokens are never stored or logged.** Auth results are cached per isolate,
  keyed by the SHA-256 of the credential. Logs show the resolved identity.
- **GitHub's signing keys** are cached for an hour, and an unknown `kid`
  refetches them at most once a minute, so made-up tokens can't make the Worker
  hammer GitHub.
- **Signatures** are verified with WebCrypto (RS256), so no RSA crate ships in
  the bundle.

## Limitations

- Removing someone's push access takes up to 5 minutes to apply (the GitHub
  check's cache).
- Compressed NARs (`.nar.xz` etc.) aren't supported: uploads must use
  `?compression=none`.
- Secrets Store is in open beta.

## Development

The crate is a member of the Cargo workspace at the repo root. Run everything
inside the dev shell:

```bash
nix develop -c cargo test           # unit tests, from the repo root
nix develop -c worker-build --dev   # build the bundle into ./build (this directory)
nix develop -c wrangler dev         # serve locally (this directory)
```

The integration tests run against `wrangler dev`. Uploads need a GitHub token
with push access to the `CF_NIX_WORKER_GITHUB_REPOSITORY` in `wrangler.toml`:

```bash
CF_NIX_WORKER_GITHUB_TOKEN=$(gh auth token) nix develop -c cargo test --features integration
```

## Dependencies

- [`worker`](https://crates.io/crates/worker) and [`worker-macros`](https://crates.io/crates/worker-macros), the Cloudflare Workers Rust SDK
- [`narinfo`](https://crates.io/crates/narinfo) for parsing and serializing `.narinfo`
- [`http-auth-basic`](https://crates.io/crates/http-auth-basic) for the auth header
- [`serde`](https://crates.io/crates/serde) and [`serde_json`](https://crates.io/crates/serde_json) for OIDC claims, rules and GitHub API responses
- [`web-sys`](https://crates.io/crates/web-sys) for WebCrypto, which verifies OIDC token signatures
- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek), [`sha2`](https://crates.io/crates/sha2), and [`base64`](https://crates.io/crates/base64) for signing and validation
