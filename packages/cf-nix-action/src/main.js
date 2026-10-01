// @ts-check
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { booleanInput, cacheURL, fail, idToken, input, mask, nixConfig, warning, whoami, write, writeNetrc } from "./runner.js";

/** Seconds between refreshes, well inside GitHub's 5-minute token lifetime. */
const REFRESH_INTERVAL = 240;

try {
  const cache = cacheURL(input("cache-url"));
  const audience = input("audience") || cache.origin;
  const refresh = booleanInput("refresh", true);

  const token = await idToken(audience);
  mask(token);

  const subject = await whoami(cache, token);
  if (subject === undefined) {
    warning(`cf-nix-cache: ${cache.origin} has no /v1/auth/whoami, so the credentials weren't checked`);
  } else {
    console.log(`cf-nix-cache: authenticated to ${cache.origin} as ${subject}`);
  }

  const tmp = process.env.RUNNER_TEMP;
  if (!tmp) throw new Error("RUNNER_TEMP is not set; is this running in GitHub Actions?");
  const netrc = join(tmp, `cf-nix-cache-${randomUUID()}.netrc`);
  writeNetrc(netrc, cache, token);
  write("GITHUB_STATE", "netrc", netrc);
  write("GITHUB_ENV", "NIX_CONFIG", nixConfig(process.env.NIX_CONFIG, netrc));
  write("GITHUB_OUTPUT", "subject", subject ?? "");
  write("GITHUB_OUTPUT", "netrc-file", netrc);

  if (refresh) {
    // Detached with no stdio, so the step can finish while it keeps running
    // into later steps. post.js stops it; the runner kills it at job end anyway.
    const log = `${netrc}.log`;
    const interval = process.env.CF_NIX_ACTION_REFRESH_INTERVAL || String(REFRESH_INTERVAL);
    const child = spawn(process.execPath, [fileURLToPath(new URL("./refresh.js", import.meta.url))], {
      detached: true,
      stdio: "ignore",
      env: {
        ...process.env,
        CF_NIX_ACTION_NETRC: netrc,
        CF_NIX_ACTION_CACHE_URL: cache.href,
        CF_NIX_ACTION_AUDIENCE: audience,
        CF_NIX_ACTION_REFRESH_INTERVAL: interval,
        CF_NIX_ACTION_LOG: log,
      },
    });
    child.unref();
    write("GITHUB_STATE", "refresher_pid", String(child.pid));
    write("GITHUB_STATE", "refresher_log", log);
    console.log(`cf-nix-cache: refreshing the token every ${interval}s for the rest of the job`);
  }
} catch (err) {
  fail(err);
}
