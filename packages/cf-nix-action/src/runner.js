// @ts-check
// A small replacement for @actions/core plus the netrc and OIDC helpers the
// action needs. Node built-ins only: this file runs straight from the git
// checkout of the tag.

import { randomUUID } from "node:crypto";
import { appendFileSync, renameSync, writeFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

/** @param {string} name */
export const input = (name) => process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`]?.trim() ?? "";

/** @param {string} name */
export const state = (name) => process.env[`STATE_${name}`] ?? "";

/** @param {string} value */
export const mask = (value) => console.log(`::add-mask::${value}`);

/** @param {string} message */
const escapeData = (message) => message.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

/** @param {string} message */
export const warning = (message) => console.log(`::warning::${escapeData(message)}`);

/** Reports an error as a workflow annotation and fails the step. @param {unknown} err */
export function fail(err) {
  console.log(`::error::${escapeData(err instanceof Error ? err.message : String(err))}`);
  process.exitCode = 1;
}

/**
 * Appends `key=value` to one of the runner's command files, using a heredoc
 * so the value may span lines.
 * @param {"GITHUB_ENV" | "GITHUB_OUTPUT" | "GITHUB_STATE"} file @param {string} key @param {string} value
 */
export const write = (file, key, value) => {
  const path = process.env[file];
  if (!path) throw new Error(`${file} is not set; is this running in GitHub Actions?`);
  const eof = `EOF_${randomUUID()}`;
  appendFileSync(path, `${key}<<${eof}\n${value}\n${eof}\n`);
};

/**
 * Parses the `cache-url` input. HTTPS is required, except for loopback hosts
 * (used by the smoke test), because the OIDC token travels in every request.
 * @param {string} value
 */
export function cacheURL(value) {
  if (!value) throw new Error("Input required and not supplied: cache-url");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`cache-url is not a valid URL: ${value}`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`cache-url must use https: ${value}`);
  }
  return url;
}

/**
 * Parses a boolean input the way GitHub documents them: `true` or `false`.
 * @param {string} name @param {boolean} fallback
 */
export function booleanInput(name, fallback) {
  const value = input(name).toLowerCase();
  if (value === "") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false: ${value}`);
}

/**
 * Requests a GitHub OIDC JWT. Retries network errors and 5xx responses,
 * because the runner's token endpoint occasionally has brief failures.
 * @param {string} audience
 * @param {{ attempts?: number, delay?: number, env?: NodeJS.ProcessEnv }} [options]
 */
export async function idToken(audience, { attempts = 3, delay = 500, env = process.env } = {}) {
  const { ACTIONS_ID_TOKEN_REQUEST_URL: url, ACTIONS_ID_TOKEN_REQUEST_TOKEN: bearer } = env;
  if (!url || !bearer) throw new Error("OIDC unavailable: add `permissions: id-token: write` to the job");

  const req = new URL(url);
  req.searchParams.set("audience", audience);

  for (let i = 1; ; i++) {
    /** @type {Response} */
    let response;
    try {
      response = await fetch(req, {
        headers: { authorization: `bearer ${bearer}` },
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      if (i >= attempts) throw err;
      await sleep(delay * 2 ** (i - 1));
      continue;
    }
    if (response.ok) {
      const { value } = /** @type {{ value?: string }} */ (await response.json());
      if (!value) throw new Error("OIDC token response had no value");
      return value;
    }
    if (response.status < 500 || i >= attempts) throw new Error(`OIDC token request failed: ${response.status}`);
    await sleep(delay * 2 ** (i - 1));
  }
}

/**
 * The netrc entry Nix sends to the cache: the Worker reads the `oidc`
 * username as "verify the password as a GitHub Actions OIDC token".
 * @param {URL} cache @param {string} token
 */
export const netrcEntry = (cache, token) => `machine ${cache.hostname}\n  login oidc\n  password ${token}\n`;

/**
 * Writes the netrc atomically with mode 0600, so a concurrent `nix copy`
 * never reads a half-written file.
 * @param {string} path @param {URL} cache @param {string} token
 */
export function writeNetrc(path, cache, token) {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, netrcEntry(cache, token), { mode: 0o600 });
  renameSync(tmp, path);
}

/**
 * Appends `netrc-file` to an existing `NIX_CONFIG`. Later lines win, so this
 * overrides any `netrc-file` set before.
 * @param {string | undefined} existing @param {string} netrc
 */
export const nixConfig = (existing, netrc) => [existing?.trimEnd(), `netrc-file = ${netrc}`].filter(Boolean).join("\n");

/** Hints for the statuses a misconfigured workflow or Worker usually produces. */
const HINTS = /** @type {Record<number, string>} */ ({
  401: "the cache rejected the OIDC token; check that audience matches the Worker's CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE",
  403: "the cache refused this workflow; check CF_NIX_WORKER_GITHUB_OWNER_ID and CF_NIX_WORKER_GITHUB_OIDC_RULES",
  500: "the cache's auth config is invalid; its logs have the reason",
});

/**
 * Asks the cache which identity the token resolves to, so a wrong audience or
 * a missing rule fails here rather than halfway through `nix copy`.
 * Returns `undefined` for a cache without the endpoint.
 * @param {URL} cache @param {string} token
 */
export async function whoami(cache, token) {
  const response = await fetch(new URL("/auth/whoami", cache), {
    headers: { authorization: `Basic ${Buffer.from(`oidc:${token}`).toString("base64")}` },
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) {
    const reason = (await response.text().catch(() => "")).trim();
    const hint = HINTS[response.status];
    throw new Error(`cache returned ${response.status}${reason ? ` (${reason})` : ""}${hint ? `: ${hint}` : ""}`);
  }
  const identity = /** @type {{ kind?: string, subject?: string }} */ (await response.json());
  if (typeof identity.subject !== "string") throw new Error("cache returned an invalid /auth/whoami response");
  return identity.subject;
}
