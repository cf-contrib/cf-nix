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
  description = "cloudflare-nix release that was deployed, or \"local\" for bundle_dir."
}

output "worker_modules_sha256" {
  value = {
    "index.js"      = sha256(local.index_js_base64)
    "index_bg.wasm" = sha256(local.index_wasm_base64)
  }
  description = "SHA-256 of each module the Worker version uploads, of its base64 content: the plan shows the modules themselves only as a sensitive value."
}
