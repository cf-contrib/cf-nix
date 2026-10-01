// @ts-check
// Runs main.js and post.js as the runner does: separate processes, inputs and
// state in INPUT_* / STATE_* variables, outputs in the command files.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { after, before, describe, it } from "node:test";
import { startStub } from "./stub.js";

const run = promisify(execFile);
const src = fileURLToPath(new URL("../src/", import.meta.url));

/** Parses `key<<EOF ... EOF` entries from a runner command file. @param {string} path */
function commands(path) {
  /** @type {Record<string, string>} */
  const out = {};
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const match = /^(.+)<<(EOF_.+)$/.exec(lines[i]);
    if (!match) continue;
    const end = lines.indexOf(match[2], i + 1);
    out[match[1]] = lines.slice(i + 1, end).join("\n");
    i = end;
  }
  return out;
}

/** @param {number} pid */
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

describe("action", () => {
  /** @type {Awaited<ReturnType<typeof startStub>>} */
  let stub;
  before(async () => {
    stub = await startStub();
  });
  after(() => stub.server.close());

  /** @param {Record<string, string>} inputs @param {Record<string, string>} [extra] */
  function env(inputs, extra = {}) {
    const dir = mkdtempSync(join(tmpdir(), "cf-nix-action-"));
    const files = Object.fromEntries(
      ["GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STATE"].map((name) => {
        const path = join(dir, name);
        writeFileSync(path, "");
        return [name, path];
      }),
    );
    return {
      files,
      env: {
        PATH: process.env.PATH,
        RUNNER_TEMP: dir,
        ACTIONS_ID_TOKEN_REQUEST_URL: `${stub.url}/oidc?api-version=2.0`,
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "stub-request-token",
        ...files,
        ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v])),
        ...extra,
      },
    };
  }

  it("writes the netrc, exports NIX_CONFIG, refreshes the token and cleans up", async () => {
    const { files, env: e } = env(
      { "cache-url": stub.url },
      { NIX_CONFIG: "substituters = https://cache.nixos.org", CF_NIX_ACTION_REFRESH_INTERVAL: "1" },
    );
    const { stdout } = await run(process.execPath, [join(src, "main.js")], { env: e });
    assert.match(stdout, /::add-mask::stub\./);
    assert.match(stdout, /authenticated to http:\/\/127\.0\.0\.1:\d+ as repo:example-org\/app/);

    const state = commands(files.GITHUB_STATE);
    const output = commands(files.GITHUB_OUTPUT);
    assert.equal(output.subject, "repo:example-org/app:ref:refs/heads/main");
    assert.equal(output["netrc-file"], state.netrc);
    assert.equal(commands(files.GITHUB_ENV).NIX_CONFIG, `substituters = https://cache.nixos.org\nnetrc-file = ${state.netrc}`);

    const first = readFileSync(state.netrc, "utf8");
    assert.match(first, /^machine 127\.0\.0\.1\n {2}login oidc\n {2}password stub\.[^.]+\.\d+\n$/);
    assert.equal(statSync(state.netrc).mode & 0o777, 0o600);

    // The refresher outlives main.js and replaces the token.
    const pid = Number(state.refresher_pid);
    assert.ok(alive(pid), "the refresher should still be running");
    await sleep(2500);
    assert.notEqual(readFileSync(state.netrc, "utf8"), first, "the token should have been refreshed");

    const post = Object.fromEntries(Object.entries(state).map(([k, v]) => [`STATE_${k}`, v]));
    await run(process.execPath, [join(src, "post.js")], { env: { ...e, ...post } });
    await sleep(200);
    assert.ok(!alive(pid), "post should stop the refresher");
    assert.ok(!existsSync(state.netrc), "post should delete the netrc");
  });

  it("doesn't start a refresher with refresh: false", async () => {
    const { files, env: e } = env({ "cache-url": stub.url, refresh: "false" });
    await run(process.execPath, [join(src, "main.js")], { env: e });
    const state = commands(files.GITHUB_STATE);
    assert.ok(state.netrc);
    assert.equal(state.refresher_pid, undefined);
  });

  it("fails before writing anything when the cache rejects the token", async () => {
    const { files, env: e } = env({ "cache-url": stub.url, audience: "https://wrong.example.com" });
    const result = await run(process.execPath, [join(src, "main.js")], { env: e }).catch((err) => err);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /::error::cache returned 401 .*CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE/);
    assert.equal(readFileSync(files.GITHUB_ENV, "utf8"), "");
    assert.equal(readFileSync(files.GITHUB_STATE, "utf8"), "");
  });

  it("post does nothing without state", async () => {
    const { env: e } = env({ "cache-url": stub.url });
    const { stdout } = await run(process.execPath, [join(src, "post.js")], { env: e });
    assert.equal(stdout, "");
  });
});
