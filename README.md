# nix-cache

> Stop babysitting a Nix cache server. Deploy this Worker, point `nix.conf` at it, and substitutes come from Cloudflare's edge.

[![CI](https://github.com/cf-contrib/cf-nix-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-nix-cache/actions/workflows/ci.yml)
[![Rust (edition 2021)](https://img.shields.io/badge/Rust-2021-black?logo=rust)](https://www.rust-lang.org/)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-5277C3?logo=nixos&logoColor=white)](https://nixos.wiki/wiki/Flakes)
[![License: MIT](https://img.shields.io/github/license/cf-contrib/cf-nix-cache)](LICENSE)

A [Nix](https://nixos.org/) binary cache that runs on Cloudflare Workers and R2. Written in Rust.

## Why a Worker, not direct R2/S3?

Nix supports S3-compatible binary caches natively via the
[`s3://`](https://nix.dev/manual/nix/2.23/store/types/s3-binary-cache-store)
store type, and R2 speaks the S3 API. You can also put a public R2 bucket
behind a custom domain and use Nix's
[HTTP Binary Cache Store](https://nix.dev/manual/nix/2.23/store/types/http-binary-cache-store)
for anonymous reads. Both are simpler than running this Worker.

What you get on top of `s3://`:

- Clients authenticate with a shared HTTP Basic token, not AWS access keys. The `s3://` store uses the AWS default credential provider chain, so every uploader needs a key pair.
- Server-side narinfo signing. The Worker holds the Nix signing key and signs uploads itself; the key never has to live on a CI runner's `secret-key-files`.
- Upload validation. The Worker parses each narinfo, checks the format, binds the StorePath to the request route, and rejects anything unsigned. `s3://` is opaque blob storage.
- `POST /` mass-query in one request. The HTTP Binary Cache protocol supports it; `s3://` falls back to one HEAD per path.

If none of that matters to you, `s3://` to R2 is less code to maintain.

Also: this is a hobby project. I wanted an excuse to spend more time with Cloudflare Workers and Rust, and a Nix cache made a good target.

## Table of contents

- [Why a Worker, not direct R2/S3?](#why-a-worker-not-direct-r2s3)
- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [HTTP API](#http-api)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Development](#development)
- [Dependencies](#dependencies)
- [License](#license)

## Features

- Speaks the same protocol as `cache.nixos.org`.
- Reads come from Cloudflare's edge.
- Storage lives in R2 (no egress to Workers).
- HTTP Basic auth on uploads.
- Optional Ed25519 signing of narinfo on the server.
- One Worker bundle: `index.js` plus `index_bg.wasm`.

## How it works

```
┌──────────┐    GET /<hash>.narinfo    ┌──────────────┐    R2 GET    ┌────────┐
│   nix    │ ────────────────────────► │  Worker (CF) │ ───────────► │   R2   │
│  client  │ ◄──────────────────────── │              │ ◄─────────── │ bucket │
└──────────┘     narinfo + .nar        └──────────────┘    object    └────────┘
                                              ▲
                                              │ PUT (Basic auth)
                                       ┌──────────────┐
                                       │  uploader    │
                                       │ (nix copy …) │
                                       └──────────────┘
```

Reads are public. Uploads need HTTP Basic auth. Everything lives in one R2 bucket.

## Quick start

### 1. Configure your Nix client

Add the deployed Worker URL to your `nix.conf`:

```ini
substituters = https://<your-worker>.workers.dev https://cache.nixos.org
trusted-public-keys = <your-key-name>:<base64-public-key> cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
```

### 2. Push a store path

```bash
export NIX_TOKEN=<token>
nix copy \
  --to "https://x-auth-token:${NIX_TOKEN}@<your-worker>.workers.dev" \
  /nix/store/<hash>-<name>
```

### 3. Pull on another machine

```bash
nix build nixpkgs#hello  # served from the Worker if cached
```

### Keep the token out of URLs

For anything beyond a one-shot push, put the token in a `netrc` file so it stays out of shell history, process lists, and CI logs:

```
machine <your-worker>.workers.dev
  login x-auth-token
  password <NIX_TOKEN>
```

Point Nix at it from `nix.conf`:

```ini
netrc-file = /home/you/.netrc
```

Then `nix copy --to https://<your-worker>.workers.dev /nix/store/...` works without embedded credentials.

## HTTP API

| Method | Path              | Auth   | Description                                |
| ------ | ----------------- | ------ | ------------------------------------------ |
| `GET`  | `/nix-cache-info` | public | Cache metadata (priority, etc.).           |
| `GET`  | `/<hash>.narinfo` | public | Narinfo for a store path.                  |
| `HEAD` | `/<hash>.narinfo` | public | Existence check for a narinfo (200 / 404). |
| `PUT`  | `/<hash>.narinfo` | basic  | Upload a narinfo.                          |
| `GET`  | `/nar/<hash>.nar` | public | NAR archive bytes.                         |
| `HEAD` | `/nar/<hash>.nar` | public | Existence check for a NAR (200 / 404).     |
| `PUT`  | `/nar/<hash>.nar` | basic  | Upload a NAR archive.                      |

**Auth:** HTTP Basic, username `x-auth-token`, password `${NIX_TOKEN}`.

**Signing:** every stored narinfo carries a `Sig:`. If the uploader didn't sign and `NIX_SECRET` is set, the Worker signs the upload itself. Otherwise the PUT returns `400`.

## Configuration

### Environment variables

| Variable             | Required    | Description                                                                                                      |
| -------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `NIX_TOKEN`          | for uploads | Password for HTTP Basic auth on `PUT` requests (username is `x-auth-token`).                                     |
| `NIX_SECRET`         | conditional | `<key-name>:<base64>` — base64 decodes to 64 Ed25519 secret-key bytes (as emitted by `nix key generate-secret`). Required unless every uploader sends pre-signed narinfo. |

### Bindings

| Binding      | Type      | Description                           |
| ------------ | --------- | ------------------------------------- |
| `NIX_BUCKET` | R2 bucket | Stores `.narinfo` and `.nar` objects. |

## Deployment

Use Terraform with the Cloudflare provider. The [`examples/terraform/`](examples/terraform/) directory has a full example that pulls the Worker bundle from this repo's GitHub Releases and deploys it to Workers + R2.

CI publishes two files to GitHub Releases:

- `build/index.js`
- `build/index_bg.wasm`

Both are required, because `index.js` imports `./index_bg.wasm` at runtime.

> `wrangler.toml` is for local testing, not production.

## Development

The Nix flake gives you a dev shell with the tooling already pinned:

```bash
nix develop -c cargo test           # run the test suite
nix develop -c worker-build --dev   # build the Worker bundle into ./build
nix develop -c wrangler dev         # serve locally via wrangler
```

## Dependencies

Runtime crates:

- [`worker`](https://crates.io/crates/worker) and [`worker-macros`](https://crates.io/crates/worker-macros), the Cloudflare Workers Rust SDK
- [`narinfo`](https://crates.io/crates/narinfo) for parsing and serializing `.narinfo`
- [`http-auth-basic`](https://crates.io/crates/http-auth-basic) for the auth header
- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek), [`sha2`](https://crates.io/crates/sha2), and [`base64`](https://crates.io/crates/base64) for signing and validation

Tooling:

- Nix, for the dev shell
- `worker-build` (from Cloudflare's `workers-rs`) for the JS + WASM bundle
- `wrangler` for local testing
- Terraform for production

## License

[MIT](LICENSE)
