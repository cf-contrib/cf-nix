# Changelog

## [0.3.0](https://github.com/cf-contrib/cf-nix-cache/compare/v0.2.0...v0.3.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* the Worker reads only the CF_NIX_CACHE_* bindings. Rename the bindings in your deployment before upgrading; the Terraform example already uses the new names.
* the NIX_TOKEN / x-auth-token upload auth is removed. Configure GITHUB_REPOSITORY and/or GITHUB_OWNER_ID, GITHUB_OIDC_AUDIENCE and GITHUB_OIDC_RULES before upgrading. The Terraform example drops the nix_token variable.

### Features

* authorize uploads by GitHub identity ([#68](https://github.com/cf-contrib/cf-nix-cache/issues/68)) ([8fd92de](https://github.com/cf-contrib/cf-nix-cache/commit/8fd92de804a7fba5fa5f74795a7bc86b1b38d0e3)), closes [#67](https://github.com/cf-contrib/cf-nix-cache/issues/67)
* prefix Worker bindings with CF_NIX_CACHE_ ([#70](https://github.com/cf-contrib/cf-nix-cache/issues/70)) ([3dceb8c](https://github.com/cf-contrib/cf-nix-cache/commit/3dceb8cbd934ddf618945f1da8a9c314ed9e492d))

## [0.2.0](https://github.com/cf-contrib/nix-cache/compare/v0.1.0...v0.2.0) (2026-05-19)


### Features

* reject unsigned narinfo uploads ([2c842e7](https://github.com/cf-contrib/nix-cache/commit/2c842e7639f70a18cb66003a33eed84c7a99ccd6))
* **terraform:** expire R2 cache objects after 45 days ([30f0d1e](https://github.com/cf-contrib/nix-cache/commit/30f0d1e40709fd329f2eaca94a3ea4377e86772a))


### Bug Fixes

* handle HEAD requests and align narinfo validation with Nix format ([bd9dd30](https://github.com/cf-contrib/nix-cache/commit/bd9dd309cb3001b6ce4c1fe8561922381dc2a6d4))

## [0.1.0](https://github.com/cf-contrib/nix-cache/compare/v0.0.1...v0.1.0) (2026-05-19)


### Features

* add basic auth to PUT endpoints ([dfdd36b](https://github.com/cf-contrib/nix-cache/commit/dfdd36b76d64283eaae0144cc87fe0f83647cb87))
* add content-type header and improve narinfo response handling ([dbc9cd8](https://github.com/cf-contrib/nix-cache/commit/dbc9cd8975585b02f8158ea82b933aa959423a77))
* implement /nix-cache-info endpoint ([1248124](https://github.com/cf-contrib/nix-cache/commit/12481242ebac56ea4558cb108ed81355cfb8d88f))
* implement GET /:hash narinfo retrieval ([dd430bf](https://github.com/cf-contrib/nix-cache/commit/dd430bfd203f06cc590ca131d2b3d6ba80f31467))
* implement GET /nar/:hash endpoint ([c065eb9](https://github.com/cf-contrib/nix-cache/commit/c065eb9a65f80bf63796b4b06734444304ba0500))
* implement nix binary cache api routes ([647a7dd](https://github.com/cf-contrib/nix-cache/commit/647a7dd1c0f4b7f58b8dcd2715c24b755317012e))
* implement POST endpoint for mass-query batch lookup ([85fa60e](https://github.com/cf-contrib/nix-cache/commit/85fa60e666737596eb717b99bebc9f7446f5d5f2))
* implement PUT endpoint for NAR upload ([4bb228b](https://github.com/cf-contrib/nix-cache/commit/4bb228bc9b82621238d26a8d33453b20565a655e))
* implement PUT endpoint for narinfo upload ([2037ed8](https://github.com/cf-contrib/nix-cache/commit/2037ed8227ab9f09f6cffa6111ad07b24b8b55f9))
* initialize cf-nix-cache cloudflare worker project ([09c9ed1](https://github.com/cf-contrib/nix-cache/commit/09c9ed1039791a0959c51e6ab7397ba56410c5ca))
* return 500 error for unimplemented endpoints ([52645bd](https://github.com/cf-contrib/nix-cache/commit/52645bd8440b513e067acfacaf5c5dffbfc75e2b))
* support .nar extension flexibility in bucket key resolution ([e933533](https://github.com/cf-contrib/nix-cache/commit/e9335338164d7bbbc4f376c34b3341de540a814e))
* validate and sign narinfo uploads ([cd36e28](https://github.com/cf-contrib/nix-cache/commit/cd36e28a8150e3c30a097595ddbf863c8484832f))
* validate narinfo uploads on PUT ([fae08e2](https://github.com/cf-contrib/nix-cache/commit/fae08e204d196584c54936a95537f2144abcb3c2))


### Bug Fixes

* add newline to narinfo output and fix unused variable ([cbcc966](https://github.com/cf-contrib/nix-cache/commit/cbcc966159fa745379b172de74457cb58c79e035))
* swap ed25519-dalek-v2 for upstream ed25519-dalek ([47cbb67](https://github.com/cf-contrib/nix-cache/commit/47cbb6768e894b6673ee1327b5eb9bb7c40402ba))
