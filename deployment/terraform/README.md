# cf-nix-cache Terraform module

> The Terraform / OpenTofu half of [cf-nix-cache](../..): deploys the released
> Worker bundle to Cloudflare Workers with its R2 bucket, bindings and a
> workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cf_nix_cache" {
  source = "git::https://github.com/cf-contrib/cf-nix-cache.git//deployment/terraform?ref=v0.6.0" # x-release-please-version

  account_id         = var.account_id
  hostname           = "cf-nix-cache.example.workers.dev"
  bucket_name        = "nix-cache"
  signing_key_secret = { secret_store_id = var.secret_store_id, secret_name = "cf-nix-cache-signing-key" }

  # Who may upload: OIDC tokens from these providers that match a claim set.
  oidc_providers = [{
    # GitHub Actions jobs in this org's repo, on main. The audience defaults
    # to the cache URL. GitHub gives tokens to every repository on github.com,
    # so pin your org in every claim set.
    issuer = "https://token.actions.githubusercontent.com"
    claims = [{
      repository_owner_id = "100000001" # gh api orgs/<org> --jq .id
      repository_id       = "200000002" # gh api repos/<org>/<repo> --jq .id
      ref                 = "refs/heads/main"
    }]
  }]
}

output "cache_url" {
  value = module.cf_nix_cache.url
}
```

The module is released with the Worker from the same tag, and by default
deploys the Worker bundle of the release its `ref` points to.

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
curl -fsS "$(tofu output -raw cache_url)/health/ready"   # 200 once the Worker is serving and configured
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
| `hostname` | yes | | `<worker_name>.<subdomain>.workers.dev`, or a custom domain (needs `zone_id`). Its URL is also the default OIDC audience. |
| `zone_id` | for a custom domain | `null` | Zone that holds a custom-domain `hostname`. |
| `bucket_name` | yes | | R2 bucket to create for `.narinfo` and `.nar` objects. |
| `expire_after_days` | no | `45` | Delete objects this many days after upload. `null` keeps them. |
| `signing_key_secret` | no | `null` | `{ secret_store_id, secret_name }` of the signing key. `null`: uploaders must sign. |
| `oidc_providers` | no | `[]` | Identity providers whose tokens may upload: `{ issuer, audience?, jwks_uri?, claims }`. `audience` defaults to the cache URL; `claims` is a list of claim sets, any one of which must match. Empty turns uploads off. See the Worker's [Authentication](../../crates/cf-nix-cache-api/README.md#authentication). |
| `release_tag` | no | this module's release | Release to deploy, e.g. `v1.2.3`, or `"latest"`. |
| `bundle_dir` | no | `null` | A local `worker-build --release` output directory to deploy instead of a release. |
| `worker_name` | no | `cf-nix-cache` | Cloudflare Worker script name. |
| `worker_compatibility_date` | no | `2026-05-14` | Workers runtime compatibility date. |

## Outputs

| Output | Description |
|---|---|
| `url` | The cache URL, for `substituters`, `nix copy --to`, and the audience uploaders request their tokens for. |
| `worker_name` | Deployed Worker script name. |
| `bucket_name` | R2 bucket backing the cache. |
| `release_tag` | Release that was deployed, or `"local"` for `bundle_dir`. |

## Upgrading

Bump the `ref` in `source` and run `tofu apply`. The module downloads that
release's bundle, uploads a new Worker version and shifts all traffic to it.

### From 0.4

Uploads authenticate with OIDC tokens from any provider you list, instead of
GitHub tokens or GitHub Actions only:

- `github_owner_id`, `github_oidc_audience` and `github_oidc_rules` become one
  `oidc_providers` entry for `https://token.actions.githubusercontent.com`. Add
  `repository_owner_id` to each of its claim sets, which used to be implied,
  and write any `*` only at the end of a pattern.
- `github_repository` is gone, and with it uploads with a person's GitHub
  token. Give people a token from an issuer such as Cloudflare Access instead.
- The bindings are renamed `CF_NIX_CACHE_API_*`. The module sets them, so
  there's nothing to do unless you read them elsewhere.

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
- The bindings are named `CF_NIX_CACHE_API_*`; the module sets them.

## Development

```sh
tofu init -backend=false
tofu test        # mocked providers: no credentials or network needed
```
