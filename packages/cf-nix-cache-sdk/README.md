# cf-nix-cache SDK

> The HTTP API of [cf-nix-cache](../..), as an OpenAPI document, and the Rust
> generated from it: the types, the server traits the [Worker](../cf-nix-cache-api)
> implements, and a client.

Everything is under `v1`:

```rust
use cf_nix_cache_sdk::v1::*;
```

## What is in it

| Feature | What it adds |
|---|---|
| (none) | The types: `Identity`, what `GET /v1/whoami` returns, and `Error`, the body of every error. |
| `server` | A trait per tag (`CacheApi`, `AuthApi`, `HealthApi`), a response enum per operation, and `build_router`, an axum router over all three that checks requests against the document before they reach a handler. |
| `client` | `HttpClient`, a method per operation, over reqwest. |

## Calling the API

```rust
use cf_nix_cache_sdk::v1::HttpClient;

let client = HttpClient::new().with_base_url("https://cf-nix-cache.example.workers.dev");
// HTTP Basic credentials: `users` with a GitHub token, or `actions` with an OIDC token.
let identity = client.get_whoami(Some("Basic dXNlcnM6Z2hvX2V4YW1wbGU=")).await?;
println!("{} {}", identity.kind, identity.subject);
```

## Generated code

[`openapi/nix/cache/v1/cachev1.yaml`](openapi/nix/cache/v1/cachev1.yaml) is the
source. `build.rs` runs [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust)
over it into `OUT_DIR` on every build that changes it, with the server and the
client only when their feature is on. None of it is checked in or edited by
hand: change the document, and the Worker fails to compile until it matches.

The generated server buffers request bodies, up to 64 MiB, which bounds NAR
uploads.
