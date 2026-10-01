// @ts-check
// Started detached by main.js. GitHub OIDC tokens expire 5 minutes after
// they're issued, and Nix reads the netrc again for every request, so
// rewriting the file keeps a long `nix copy` authenticated. Refreshed tokens
// are never printed, so they don't need masking.
import { appendFileSync, existsSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { cacheURL, idToken, writeNetrc } from "./runner.js";

const {
  CF_NIX_ACTION_NETRC: netrc,
  CF_NIX_ACTION_CACHE_URL: url,
  CF_NIX_ACTION_AUDIENCE: audience,
  CF_NIX_ACTION_REFRESH_INTERVAL: interval,
  CF_NIX_ACTION_LOG: log,
} = process.env;
if (!netrc || !url || !audience || !interval || !log) process.exit(2);

const cache = cacheURL(url);
/** @param {string} line */
const note = (line) => appendFileSync(log, `${new Date().toISOString()} ${line}\n`);

for (;;) {
  await sleep(Number(interval) * 1000);
  // post.js deletes the netrc at job end; don't bring it back.
  if (!existsSync(netrc)) break;
  try {
    writeNetrc(netrc, cache, await idToken(audience));
    note("refreshed");
  } catch (err) {
    note(`refresh failed: ${err instanceof Error ? err.message : err}`);
  }
}
