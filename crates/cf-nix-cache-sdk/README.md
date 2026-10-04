# cf-nix-cache-sdk

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
| (none) | The types: `Error`, the body of every error, and the narinfo format, `NarInfo`. |
| `server` | `CacheServiceApi`, a response enum per operation, and `cache_service_api_router`, an axum router over it that checks requests against the document before they reach a handler. `HealthHandler`, which answers the health endpoints beside it, `/health/live` and `/health/ready`. |
| `signing` | `NarInfoSigKey`, which signs a narinfo the way Nix does. |
| `client` | `HttpClient`, a method per operation, over reqwest, and `HealthClient`, which asks the health endpoints. |

## Calling the API

```rust
use cf_nix_cache_sdk::v1::HttpClient;

let client = HttpClient::new().with_base_url("https://cf-nix-cache.example.workers.dev");
let info = client.get_nar_info("j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0").await?;

// Uploads take an OIDC token as the password of HTTP Basic credentials.
let authorization = format!("Basic {}", base64(format!("oidc:{token}")));
client.put_nar_info("j5m1qd2dbsmhq0mw13yb8wijnm3pq4z0", Some(authorization), info).await?;
```

## Generated code

[`openapi/nix/cache/v1/cachev1.tsp`](openapi/nix/cache/v1/cachev1.tsp) is the
source, in [TypeSpec](https://typespec.io). It compiles to the OpenAPI document,
[`cachev1.yaml`](openapi/nix/cache/v1/cachev1.yaml) beside it, which is checked
in so a Rust build needs no Node:

```bash
cd openapi
nix develop -c npm ci             # once
nix develop -c npm run generate   # after editing the .tsp
```

CI regenerates the document and fails if it differs from the one checked in.

`build.rs` runs [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust)
over the document into `OUT_DIR` on every build that changes it, with the server
and the client only when their feature is on. None of that is checked in or
edited by hand: change the API, and the Worker fails to compile until it
matches.

The document is OpenAPI 3.0, not 3.1. TypeSpec writes a 3.1 NAR body as
`contentMediaType`, and openapi-to-rust only takes a body as bytes when its
schema is `format: binary`.

The generated server buffers request bodies, up to 64 MiB, which bounds NAR
uploads.
