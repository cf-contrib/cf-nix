# Worker script (logical resource — no content yet).
resource "cloudflare_worker" "nix_cache" {
  account_id = var.account_id
  name       = var.worker_name

  subdomain = {
    enabled = true
  }
}

# Upload a new version on every asset / binding change. The modules list
# carries both the JS entry and the wasm module, matching what worker-build
# emits and what `index.js` imports via `./index_bg.wasm`.
resource "cloudflare_worker_version" "nix_cache" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.nix_cache.id
  compatibility_date = var.worker_compatibility_date
  main_module        = "index.js"

  modules = [
    {
      name           = "index.js"
      content_type   = "application/javascript+module"
      content_base64 = base64encode(data.http.index_js.response_body)
    },
    {
      name           = "index_bg.wasm"
      content_type   = "application/wasm"
      content_base64 = data.http.index_wasm.response_body_base64
    },
  ]

  bindings = concat(
    [
      {
        name        = "CF_NIX_WORKER_BUCKET"
        type        = "r2_bucket"
        bucket_name = cloudflare_r2_bucket.nix.name
      },
      {
        name = "CF_NIX_WORKER_SECRET"
        type = "secret_text"
        text = var.nix_secret
      },
    ],
    # Upload auth: a mechanism is on only when its bindings exist.
    [
      for name, text in local.auth_vars : {
        name = name
        type = "plain_text"
        text = text
      } if text != null
    ],
  )
}

locals {
  auth_vars = {
    CF_NIX_WORKER_GITHUB_REPOSITORY    = var.github_repository
    CF_NIX_WORKER_GITHUB_OWNER_ID      = length(var.github_oidc_rules) == 0 ? null : var.github_owner_id
    CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE = length(var.github_oidc_rules) == 0 ? null : var.github_oidc_audience
    CF_NIX_WORKER_GITHUB_OIDC_RULES    = length(var.github_oidc_rules) == 0 ? null : jsonencode(var.github_oidc_rules)
  }
}

# Promote the new version to 100% of traffic.
resource "cloudflare_workers_deployment" "nix_cache" {
  account_id  = var.account_id
  script_name = cloudflare_worker.nix_cache.name
  strategy    = "percentage"

  versions = [
    {
      percentage = 100
      version_id = cloudflare_worker_version.nix_cache.id
    },
  ]
}

# R2 bucket for cached .narinfo / .nar objects.
resource "cloudflare_r2_bucket" "nix" {
  account_id = var.account_id
  name       = var.r2_bucket_name
}

# Expire cached objects 45 days after upload. Nix re-uploads on every build,
# so this just bounds storage cost without losing real cache value.
# `max_age` is in seconds: 45 * 24 * 60 * 60 = 3_888_000.
resource "cloudflare_r2_bucket_lifecycle" "nix" {
  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.nix.name

  rules = [
    {
      id      = "delete-after-45-days"
      enabled = true
      conditions = {
        prefix = ""
      }
      delete_objects_transition = {
        condition = {
          type    = "Age"
          max_age = 3888000
        }
      }
    },
  ]
}
