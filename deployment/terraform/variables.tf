variable "account_id" {
  type        = string
  description = "Cloudflare account ID that owns the Worker and the R2 bucket."
}

variable "hostname" {
  type        = string
  description = "The cache's hostname, which is also the default OIDC audience: <worker_name>.<subdomain>.workers.dev, or a custom domain such as nix-cache.example.com (needs zone_id)."

  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.hostname))
    error_message = "hostname must be a bare lowercase hostname, without a scheme, port or path."
  }

  validation {
    condition     = !endswith(var.hostname, ".workers.dev") || (startswith(var.hostname, "${var.worker_name}.") && length(split(".", var.hostname)) == 4)
    error_message = "A workers.dev hostname must be ${var.worker_name}.<subdomain>.workers.dev: Cloudflare serves the Worker under its name."
  }
}

variable "zone_id" {
  type        = string
  description = "Zone ID of the zone that holds a custom-domain hostname. Not used for workers.dev."
  default     = null

  validation {
    condition     = (var.zone_id == null) == endswith(var.hostname, ".workers.dev")
    error_message = "Set zone_id for a custom domain, and not for a workers.dev hostname."
  }
}

variable "bucket_name" {
  type        = string
  description = "R2 bucket to create for .narinfo and .nar objects."
}

variable "expire_after_days" {
  type        = number
  description = "Delete cached objects this many days after upload. null keeps them forever."
  default     = 45

  validation {
    condition     = var.expire_after_days == null || var.expire_after_days >= 1
    error_message = "expire_after_days must be at least 1, or null."
  }
}

variable "signing_key_secret" {
  type = object({
    secret_store_id = string
    secret_name     = string
  })
  description = "Secrets Store secret holding the narinfo signing key, <key-name>:<base64> as emitted by `nix key generate-secret`. Terraform only references it; the key never enters state. null means every uploader must send signed narinfo."
  default     = null
}

variable "github_repository" {
  type        = string
  description = "owner/repo. GitHub users with push access to it can upload with their own GitHub token. null turns this off."
  default     = null
}

variable "github_owner_id" {
  type        = string
  description = "Numeric ID of the GitHub org or user whose repos may upload from GitHub Actions (gh api orgs/<org> --jq .id). Required with github_oidc_rules."
  default     = null
}

variable "github_oidc_audience" {
  type        = string
  description = "Expected aud of GitHub Actions OIDC tokens. Defaults to the cache URL, which is what the action requests."
  default     = null
}

variable "github_oidc_rules" {
  type        = list(map(string))
  description = "GitHub Actions OIDC claim rules; a token is accepted if any rule matches. Empty turns OIDC off."
  default     = []

  validation {
    condition     = length(var.github_oidc_rules) == 0 || var.github_owner_id != null
    error_message = "github_oidc_rules needs github_owner_id."
  }
}

variable "release_tag" {
  type        = string
  description = "cf-nix-cache release to deploy, e.g. v1.2.3, or \"latest\". Defaults to the release this module comes from."
  default     = "v0.4.0" # x-release-please-version
}

variable "bundle_dir" {
  type        = string
  description = "Path to a locally built Worker bundle (worker-build --release), containing index.js and index_bg.wasm. Deploys it instead of downloading a release."
  default     = null
}

variable "worker_name" {
  type        = string
  description = "Cloudflare Worker script name."
  default     = "cf-nix-cache"
}

variable "worker_compatibility_date" {
  type        = string
  description = "Workers runtime compatibility date."
  default     = "2026-05-14"
}
