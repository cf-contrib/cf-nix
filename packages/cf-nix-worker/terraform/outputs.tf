output "url" {
  value       = local.url
  description = "The cache URL: use it as the action's cache-url, in substituters, and with nix copy --to."
}

output "worker_name" {
  value       = cloudflare_worker.this.name
  description = "Deployed Worker script name."
}

output "bucket_name" {
  value       = cloudflare_r2_bucket.this.name
  description = "R2 bucket backing the cache."
}

output "release_tag" {
  value       = var.bundle_dir != null ? "local" : data.github_release.this[0].release_tag
  description = "cf-nix-cache release that was deployed, or \"local\" for bundle_dir."
}
