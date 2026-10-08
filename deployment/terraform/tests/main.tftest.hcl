# Plans the module with mocked providers: no credentials or network needed.
# Covers the bindings for each auth setup, URL modes, the signing key, the
# bucket lifecycle and local bundles.
mock_provider "cloudflare" {}
mock_provider "github" {}
mock_provider "http" {}

override_data {
  target = data.github_release.this
  values = {
    assets = [
      for name in ["index.js", "index_bg.wasm"] : {
        name                 = name
        browser_download_url = "https://example.com/${name}"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-01T00:00:00Z"
        id                   = 1
        label                = ""
        node_id              = "RA_test"
        size                 = 1
        updated_at           = "2026-10-01T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cloudflare-nix/releases/assets/1"
      }
    ]
  }
}

override_data {
  target = data.http.index_js
  values = { response_body = "export default {};" }
}

override_data {
  target = data.http.index_wasm
  values = { response_body_base64 = "AGFzbQEAAAA=" }
}

variables {
  account_id  = "0123456789abcdef0123456789abcdef"
  hostname    = "cloudflare-nix-api.example.workers.dev"
  bucket_name = "nix-cache"
}

run "defaults" {
  command = plan

  assert {
    condition     = [for b in cloudflare_worker_version.this.bindings : b.name] == ["CLOUDFLARE_NIX_API_BUCKET"]
    error_message = "without auth or a signing key, only the bucket should be bound"
  }

  assert {
    condition     = cloudflare_worker.this.subdomain.enabled && length(cloudflare_workers_custom_domain.this) == 0
    error_message = "a workers.dev hostname should use the subdomain"
  }

  assert {
    condition     = output.url == "https://cloudflare-nix-api.example.workers.dev"
    error_message = "url should be the workers.dev URL"
  }

  assert {
    condition     = cloudflare_r2_bucket_lifecycle.this[0].rules[0].delete_objects_transition.condition.max_age == 45 * 24 * 60 * 60
    error_message = "objects should expire after 45 days by default"
  }

  assert {
    condition     = output.release_tag == var.release_tag
    error_message = "the release bundle should be deployed"
  }
}

run "signing_key_from_secrets_store" {
  command = plan

  variables {
    signing_key_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cloudflare-nix-signing-key" }
  }

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CLOUDFLARE_NIX_API_SECRET" && b.type == "secrets_store_secret" && b.secret_name == "cloudflare-nix-signing-key"
    ])
    error_message = "the signing key should be a Secrets Store binding"
  }

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.type == "secret_text"]) == 0
    error_message = "no secret_text binding should be created"
  }
}

run "oidc_providers" {
  command = plan

  variables {
    oidc_providers = [
      {
        issuer = "https://token.actions.githubusercontent.com"
        claims = [{ repository_owner_id = "100000001", ref = "refs/heads/main" }]
      },
      {
        issuer   = "https://example.cloudflareaccess.com"
        audience = "0123456789abcdef"
        jwks_uri = "https://example.cloudflareaccess.com/cdn-cgi/access/certs"
        claims   = [{ email = "uploader@example.com" }]
      },
      {
        issuer = "https://cloudflare-sts-api.example.com"
        typ    = "at+jwt"
        claims = [{ profile = "nix-push" }]
      },
    ]
  }

  assert {
    condition = { for b in cloudflare_worker_version.this.bindings : b.name => jsondecode(b.text) if b.type == "plain_text" } == {
      CLOUDFLARE_NIX_API_OIDC_PROVIDERS = [
        {
          issuer   = "https://token.actions.githubusercontent.com"
          audience = "https://cloudflare-nix-api.example.workers.dev"
          claims   = [{ ref = "refs/heads/main", repository_owner_id = "100000001" }]
        },
        {
          issuer   = "https://example.cloudflareaccess.com"
          audience = "0123456789abcdef"
          jwks_uri = "https://example.cloudflareaccess.com/cdn-cgi/access/certs"
          claims   = [{ email = "uploader@example.com" }]
        },
        {
          issuer   = "https://cloudflare-sts-api.example.com"
          audience = "https://cloudflare-nix-api.example.workers.dev"
          typ      = "at+jwt"
          claims   = [{ profile = "nix-push" }]
        },
      ]
    }
    error_message = "the providers should be bound, the audience defaulting to the cache URL, and an unset jwks_uri or typ left out"
  }
}

run "uploads_off_without_providers" {
  command = plan

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.name == "CLOUDFLARE_NIX_API_OIDC_PROVIDERS"]) == 0
    error_message = "without providers, no auth binding should be created"
  }
}

run "issuers_need_claims" {
  command = plan

  variables {
    oidc_providers = [{ issuer = "https://issuer.example.com", claims = [] }]
  }

  expect_failures = [var.oidc_providers]
}

run "custom_domain" {
  command = plan

  variables {
    hostname = "nix-cache.example.com"
    zone_id  = "fedcba9876543210fedcba9876543210"
  }

  assert {
    condition     = !cloudflare_worker.this.subdomain.enabled && length(cloudflare_workers_custom_domain.this) == 1
    error_message = "a custom domain should disable workers.dev and add the custom domain"
  }

  assert {
    condition     = output.url == "https://nix-cache.example.com"
    error_message = "url should be the custom domain"
  }
}

run "custom_domain_needs_zone_id" {
  command = plan

  variables {
    hostname = "nix-cache.example.com"
  }

  expect_failures = [var.zone_id]
}

run "workers_dev_hostname_must_match_worker_name" {
  command = plan

  variables {
    hostname = "other.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "no_expiry" {
  command = plan

  variables {
    expire_after_days = null
  }

  assert {
    condition     = length(cloudflare_r2_bucket_lifecycle.this) == 0
    error_message = "expire_after_days = null should not create a lifecycle rule"
  }
}

run "local_bundle" {
  command = plan

  variables {
    bundle_dir = "tests/fixtures/bundle"
  }

  assert {
    condition     = length(data.github_release.this) == 0 && output.release_tag == "local"
    error_message = "a local bundle should not download a release"
  }

  assert {
    condition     = one([for m in cloudflare_worker_version.this.modules : m.content_base64 if m.name == "index_bg.wasm"]) == filebase64("tests/fixtures/bundle/index_bg.wasm")
    error_message = "the local wasm should be uploaded"
  }
}
