output "worker_name" {
  value       = cloudflare_worker.nix_cache.name
  description = "Deployed Worker script name. Pair with your account's *.workers.dev subdomain to construct the cache URL."
}

output "r2_bucket_name" {
  value       = cloudflare_r2_bucket.nix.name
  description = "R2 bucket backing the cache."
}
