locals {
  custom_domain = !endswith(var.hostname, ".workers.dev")
  url           = "https://${var.hostname}"

  # Upload auth: off unless an issuer is configured. Unset optional fields are
  # left out rather than sent as null.
  auth_vars = {
    CF_NIX_API_OIDC_PROVIDERS = length(var.oidc_providers) == 0 ? null : jsonencode([
      for i in var.oidc_providers : merge(
        { issuer = i.issuer, audience = coalesce(i.audience, local.url), claims = i.claims },
        i.jwks_uri == null ? {} : { jwks_uri = i.jwks_uri },
        i.typ == null ? {} : { typ = i.typ },
      )
    ])
  }
}

# Worker script, reachable on its workers.dev URL or on the custom domain.
resource "cloudflare_worker" "this" {
  account_id = var.account_id
  name       = var.worker_name

  subdomain = {
    enabled = !local.custom_domain
  }

  # Uploads are logged with the identity they resolved to.
  observability = {
    enabled = true
    logs = {
      enabled         = true
      invocation_logs = false
    }
  }
}

# Upload a new version on every bundle or binding change. The modules list
# carries both the JS entry and the wasm module, matching what worker-build
# emits and what `index.js` imports via `./index_bg.wasm`.
resource "cloudflare_worker_version" "this" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.this.id
  compatibility_date = var.worker_compatibility_date
  main_module        = "index.js"

  modules = [
    {
      name           = "index.js"
      content_type   = "application/javascript+module"
      content_base64 = local.index_js_base64
    },
    {
      name           = "index_bg.wasm"
      content_type   = "application/wasm"
      content_base64 = local.index_wasm_base64
    },
  ]

  bindings = concat(
    [
      {
        name        = "CF_NIX_API_BUCKET"
        type        = "r2_bucket"
        bucket_name = cloudflare_r2_bucket.this.name
      },
    ],
    # Only ever from Secrets Store, so the signing key never enters Terraform state.
    var.signing_key_secret == null ? [] : [
      {
        name        = "CF_NIX_API_SECRET"
        type        = "secrets_store_secret"
        store_id    = var.signing_key_secret.secret_store_id
        secret_name = var.signing_key_secret.secret_name
      },
    ],
    [
      for name, text in local.auth_vars : {
        name = name
        type = "plain_text"
        text = text
      } if text != null
    ],
  )
}

# Promote the new version to 100% of traffic.
resource "cloudflare_workers_deployment" "this" {
  account_id  = var.account_id
  script_name = cloudflare_worker.this.name
  strategy    = "percentage"

  versions = [
    {
      percentage = 100
      version_id = cloudflare_worker_version.this.id
    },
  ]
}

resource "cloudflare_workers_custom_domain" "this" {
  count = local.custom_domain ? 1 : 0

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = var.hostname
  service    = cloudflare_worker.this.name

  depends_on = [cloudflare_workers_deployment.this]
}

# R2 bucket for cached .narinfo / .nar objects.
resource "cloudflare_r2_bucket" "this" {
  account_id = var.account_id
  name       = var.bucket_name
}

# Nix re-uploads paths on every build that produces them, so expiring old
# objects bounds storage cost without losing much cache value.
resource "cloudflare_r2_bucket_lifecycle" "this" {
  count = var.expire_after_days == null ? 0 : 1

  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.this.name

  rules = [
    {
      id      = "delete-after-${var.expire_after_days}-days"
      enabled = true
      conditions = {
        prefix = ""
      }
      delete_objects_transition = {
        condition = {
          type    = "Age"
          max_age = var.expire_after_days * 24 * 60 * 60
        }
      }
    },
  ]
}
