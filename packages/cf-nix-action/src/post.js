// @ts-check
// Stops the refresher and deletes the netrc at job end. Never fails the job:
// the runner kills the refresher and the token expires on its own anyway.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { state, warning } from "./runner.js";

const pid = Number(state("refresher_pid"));
const log = state("refresher_log");
const netrc = state("netrc");

if (pid) {
  try {
    process.kill(pid, "SIGTERM");
  } catch (err) {
    // ESRCH: it already exited.
    if (/** @type {NodeJS.ErrnoException} */ (err).code !== "ESRCH") {
      warning(`cf-nix-cache: stopping the token refresher failed (${err instanceof Error ? err.message : err})`);
    }
  }
}

if (log && existsSync(log)) {
  const failures = readFileSync(log, "utf8").split("\n").filter((line) => line.includes("refresh failed"));
  if (failures.length > 0) {
    warning(`cf-nix-cache: ${failures.length} token refresh(es) failed; last: ${failures.at(-1)}`);
  }
  rmSync(log, { force: true });
}

if (netrc) {
  try {
    rmSync(netrc, { force: true });
    console.log(`cf-nix-cache: deleted ${netrc}`);
  } catch (err) {
    warning(`cf-nix-cache: deleting ${netrc} failed (${err instanceof Error ? err.message : err})`);
  }
}
