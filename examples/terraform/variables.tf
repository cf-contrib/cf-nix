variable "account_id" {
  type        = string
  description = "Cloudflare account ID that owns the Worker and R2 bucket."
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

variable "r2_bucket_name" {
  type        = string
  description = "R2 bucket name used to store .narinfo and .nar objects."
}

variable "nix_token" {
  type        = string
  description = "Legacy shared upload token (HTTP Basic, username x-auth-token). Leave null to turn it off."
  sensitive   = true
  default     = null
}

variable "github_repository" {
  type        = string
  description = "owner/repo. GitHub users with push access to it can upload with their own GitHub token (username github). Leave null to turn it off."
  default     = null
}

variable "github_owner_id" {
  type        = string
  description = "Numeric ID of the GitHub org or user whose repos may upload from GitHub Actions via OIDC. Required with github_oidc_rules."
  default     = null
}

variable "github_oidc_audience" {
  type        = string
  description = "Expected aud of GitHub Actions OIDC tokens, e.g. the cache URL. Required with github_oidc_rules."
  default     = null
}

variable "github_oidc_rules" {
  type        = list(map(string))
  description = "GitHub Actions OIDC claim rules; a token is accepted if any rule matches. Empty turns OIDC off."
  default     = []

  validation {
    condition     = length(var.github_oidc_rules) == 0 || (var.github_owner_id != null && var.github_oidc_audience != null)
    error_message = "github_oidc_rules needs github_owner_id and github_oidc_audience."
  }
}

variable "nix_secret" {
  type        = string
  description = "Ed25519 signing secret as <key-name>:<base64> (as emitted by `nix key generate-secret`). The Worker rejects unsigned narinfo, so this is required unless every uploader pre-signs."
  sensitive   = true
}

