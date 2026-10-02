# cf-nix-cache Terraform module

> The Terraform / OpenTofu half of [cf-nix-cache](../..): deploys the released
> Worker bundle to Cloudflare Workers with its R2 bucket, bindings and a
> workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cf_nix_cache" {
  source = "git::https://github.com/cf-contrib/cf-nix-cache.git//deployment/terraform?ref=v0.4.0" # x-release-please-version

  account_id         = var.account_id
  hostname           = "cf-nix-cache.example.workers.dev"
  bucket_name        = "nix-cache"
  signing_key_secret = { secret_store_id = var.secret_store_id, secret_name = "cf-nix-cache-signing-key" }

  # People: anyone with push access to this repo can upload with their GitHub token.
  github_repository = "example-org/nix-cache-access"

  # GitHub Actions: OIDC tokens from this org's repos that match a rule.
  github_owner_id   = "100000001" # gh api orgs/<org> --jq .id
  github_oidc_rules = [{ repository_id = "200000002", ref = "refs/heads/main" }]
}

output "cache_url" {
  value = module.cf_nix_cache.url
}
```

The module is released with the Worker and the action from the same tag, and
by default deploys the Worker bundle of the release its `ref` points to.

## Prerequisites

- Terraform or OpenTofu >= 1.9.
- A narinfo signing key in [Secrets Store](https://developers.cloudflare.com/secrets-store/) (open beta), unless every uploader sends signed narinfo. See [Usage](#usage).
- An API token for deploying, exported as `CLOUDFLARE_API_TOKEN`, with:
  - **Account → Workers Scripts: Edit**
  - **Account → Workers R2 Storage: Edit**
  - **Account → Secrets Store: Edit**, to bind the signing key
  - **Zone → Workers Routes: Edit** on the cache's zone, only for a custom domain
- (Optional) `GITHUB_TOKEN` if you hit anonymous GitHub API rate limits while downloading the release.

## Usage

```sh
# Generate the signing key and store it once. Wrangler prompts for the value:
# paste the whole <key-name>:<base64> line.
nix key generate-secret --key-name cache.example.com-1
wrangler secrets-store store list --remote     # note the store ID
wrangler secrets-store secret create <store-id> --name cf-nix-cache-signing-key --scopes workers --remote

export CLOUDFLARE_API_TOKEN=...
tofu init
tofu apply
curl -fsS "$(tofu output -raw cache_url)/healthz"   # 500 if the config or the signing key is wrong
```

Terraform only references the secret by store ID and name. The key never
enters Terraform state or the plan. Clients need the matching public key in
`trusted-public-keys`: get it with
`nix key convert-secret-to-public < secret-key-file`.

Then set up upload credentials as described in the Worker's
[Authentication](../../crates/cf-nix-cache-api/README.md#authentication) section, and push with
`nix copy --to '<url>?compression=none'`: the cache stores uncompressed NARs.

## Inputs

| Variable | Required | Default | Description |
|---|---|---|---|
| `account_id` | yes | | Cloudflare account ID. |
| `hostname` | yes | | `<worker_name>.<subdomain>.workers.dev`, or a custom domain (needs `zone_id`). Also the default OIDC audience. |
| `zone_id` | for a custom domain | `null` | Zone that holds a custom-domain `hostname`. |
| `bucket_name` | yes | | R2 bucket to create for `.narinfo` and `.nar` objects. |
| `expire_after_days` | no | `45` | Delete objects this many days after upload. `null` keeps them. |
| `signing_key_secret` | no | `null` | `{ secret_store_id, secret_name }` of the signing key. `null`: uploaders must sign. |
| `github_repository` | no | `null` | `owner/repo`; GitHub users with push access to it can upload. |
| `github_owner_id` | with rules | `null` | Numeric GitHub org/user ID whose repos may upload from Actions. |
| `github_oidc_audience` | no | the cache URL | Expected `aud` of Actions OIDC tokens. Set it only if clients request another audience. |
| `github_oidc_rules` | no | `[]` | OIDC claim rules (list of maps); any one must match. Empty turns OIDC off. |
| `release_tag` | no | this module's release | Release to deploy, e.g. `v1.2.3`, or `"latest"`. |
| `bundle_dir` | no | `null` | A local `worker-build --release` output directory to deploy instead of a release. |
| `worker_name` | no | `cf-nix-cache` | Cloudflare Worker script name. |
| `worker_compatibility_date` | no | `2026-05-14` | Workers runtime compatibility date. |

## Outputs

| Output | Description |
|---|---|
| `url` | The cache URL, for `substituters`, `nix copy --to` and the action's `cache-url`. |
| `worker_name` | Deployed Worker script name. |
| `bucket_name` | R2 bucket backing the cache. |
| `release_tag` | Release that was deployed, or `"local"` for `bundle_dir`. |

## Upgrading

Bump the `ref` in `source` and run `tofu apply`. The module downloads that
release's bundle, uploads a new Worker version and shifts all traffic to it.

## Migrating from `examples/terraform`

The example was a root module; this is a child module. To keep the existing
Worker and bucket, add `moved` blocks next to the `module` block before the
first `apply`:

```hcl
moved {
  from = cloudflare_worker.nix_cache
  to   = module.cf_nix_cache.cloudflare_worker.this
}
moved {
  from = cloudflare_worker_version.nix_cache
  to   = module.cf_nix_cache.cloudflare_worker_version.this
}
moved {
  from = cloudflare_workers_deployment.nix_cache
  to   = module.cf_nix_cache.cloudflare_workers_deployment.this
}
moved {
  from = cloudflare_r2_bucket.nix
  to   = module.cf_nix_cache.cloudflare_r2_bucket.this
}
moved {
  from = cloudflare_r2_bucket_lifecycle.nix
  to   = module.cf_nix_cache.cloudflare_r2_bucket_lifecycle.this[0]
}
```

- `r2_bucket_name` is now `bucket_name`, and `hostname` is new.
- `nix_secret` is gone: put the key in Secrets Store and set `signing_key_secret`. It then no longer sits in your Terraform state; remove the old value from any `terraform.tfvars`.
- The bindings are named `CF_NIX_WORKER_*`; the module sets them.

## Development

```sh
tofu init -backend=false
tofu test        # mocked providers: no credentials or network needed
```
