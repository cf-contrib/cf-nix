# cf-nix-cache action

> The GitHub Actions half of [cf-nix-cache](../..): authenticates `nix copy`
> uploads to the cache with the job's GitHub OIDC token, so no workflow stores a
> cache secret.

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v7
  - uses: DeterminateSystems/nix-installer-action@v23
  - run: nix build .#app

  - uses: cf-contrib/cf-nix-cache@v0.3.0 # x-release-please-version
    with:
      cache-url: https://cf-nix-cache.example.workers.dev
  - run: nix copy --to https://cf-nix-cache.example.workers.dev ./result
```

The Worker must allow the job: its `CF_NIX_WORKER_GITHUB_OWNER_ID` must own the
repo, and one of its `CF_NIX_WORKER_GITHUB_OIDC_RULES` must match the job's
claims. See the root README's [CI: GitHub Actions OIDC](../../README.md#ci-github-actions-oidc).

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `cache-url` | yes | | Cache base URL. `https` only, except loopback hosts. |
| `audience` | no | origin of `cache-url` | OIDC audience. Must equal the Worker's `CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE`, which the Terraform module defaults to the cache URL. |
| `refresh` | no | `true` | Keep the token fresh for the rest of the job. |

## Outputs

| Output | Description |
|---|---|
| `subject` | The identity the cache resolved the token to, e.g. `repo:example-org/app:ref:refs/heads/main`. |
| `netrc-file` | Path of the netrc file. |

## What it does

1. Requests an OIDC token for `audience` (the job needs `permissions: id-token: write`) and masks it.
2. Calls `GET <cache-url>/auth/whoami` with it, and fails the step with the cache's reason on `401` or `403`. A wrong audience or a missing rule then fails here, not halfway through `nix copy`. A cache without the endpoint gets a warning.
3. Writes `$RUNNER_TEMP/cf-nix-cache-<uuid>.netrc` (mode `0600`) with `machine <host> login oidc password <token>`, and appends `netrc-file = <path>` to `NIX_CONFIG` for the rest of the job, keeping any existing `NIX_CONFIG`.
4. With `refresh`, starts a background process that rewrites the netrc with a fresh token every 4 minutes. GitHub OIDC tokens expire 5 minutes after they're issued, and Nix reads the netrc again for every request, so uploads longer than that keep working.
5. At job end, the post step stops the refresher, reports failed refreshes as a warning, and deletes the netrc.

Refreshed tokens are written only to the netrc and are never printed, so they aren't masked.

## Development

The action has no dependencies and runs straight from the git checkout of the tag, using Node built-ins only.

```sh
nix develop -c npm test   # from packages/cf-nix-action
```

CI also runs the action with `uses: ./` against [`test/stub.js`](test/stub.js), which stands in for the runner's OIDC endpoint and the cache's `/auth/whoami`.
