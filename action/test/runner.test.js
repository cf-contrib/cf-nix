// @ts-check
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { booleanInput, cacheURL, idToken, netrcEntry, nixConfig, whoami, write, writeNetrc } from "../src/runner.js";
import { startStub } from "./stub.js";

const dir = mkdtempSync(join(tmpdir(), "cf-nix-cache-"));

describe("cacheURL", () => {
  it("accepts https and loopback http", () => {
    assert.equal(cacheURL("https://cf-nix-cache.example.workers.dev").hostname, "cf-nix-cache.example.workers.dev");
    assert.equal(cacheURL("http://127.0.0.1:8787").port, "8787");
    assert.equal(cacheURL("http://localhost").hostname, "localhost");
  });

  it("rejects missing, invalid and plain-http URLs", () => {
    assert.throws(() => cacheURL(""), /required/);
    assert.throws(() => cacheURL("not a url"), /not a valid URL/);
    assert.throws(() => cacheURL("http://cache.example.com"), /must use https/);
  });
});

describe("booleanInput", () => {
  it("parses true and false, with a fallback", () => {
    process.env.INPUT_REFRESH = "false";
    assert.equal(booleanInput("refresh", true), false);
    process.env.INPUT_REFRESH = "TRUE";
    assert.equal(booleanInput("refresh", false), true);
    delete process.env.INPUT_REFRESH;
    assert.equal(booleanInput("refresh", true), true);
  });

  it("rejects anything else", () => {
    process.env.INPUT_REFRESH = "yes";
    assert.throws(() => booleanInput("refresh", true), /true or false/);
    delete process.env.INPUT_REFRESH;
  });
});

describe("netrc", () => {
  const cache = new URL("https://cf-nix-cache.example.workers.dev");

  it("uses the oidc username for the cache host", () => {
    assert.equal(
      netrcEntry(cache, "jwt"),
      "machine cf-nix-cache.example.workers.dev\n  login actions\n  password jwt\n",
    );
  });

  it("writes atomically with mode 0600", () => {
    const path = join(dir, "atomic.netrc");
    writeNetrc(path, cache, "first");
    writeNetrc(path, cache, "second");
    assert.match(readFileSync(path, "utf8"), /password second/);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith(".tmp")), []);
  });
});

describe("nixConfig", () => {
  it("adds netrc-file after any existing config", () => {
    assert.equal(nixConfig(undefined, "/tmp/n"), "netrc-file = /tmp/n");
    assert.equal(nixConfig("", "/tmp/n"), "netrc-file = /tmp/n");
    assert.equal(nixConfig("substituters = https://x\n", "/tmp/n"), "substituters = https://x\nnetrc-file = /tmp/n");
  });
});

describe("write", () => {
  it("appends a heredoc to the command file", () => {
    const file = join(dir, "env");
    writeFileSync(file, "");
    process.env.GITHUB_ENV = file;
    write("GITHUB_ENV", "NIX_CONFIG", "a = 1\nb = 2");
    const [first, ...rest] = readFileSync(file, "utf8").split("\n");
    assert.match(first, /^NIX_CONFIG<<EOF_[0-9a-f-]+$/);
    assert.deepEqual(rest, ["a = 1", "b = 2", first.split("<<")[1], ""]);
  });
});

describe("with a stub", () => {
  /** @type {Awaited<ReturnType<typeof startStub>>} */
  let stub;
  before(async () => {
    stub = await startStub({ failures: 1, audience: "https://cache.example.com" });
  });
  after(() => stub.server.close());

  const env = () => ({
    ACTIONS_ID_TOKEN_REQUEST_URL: `${stub.url}/oidc?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "stub-request-token",
  });

  it("idToken retries 5xx and requests the audience", async () => {
    const token = await idToken("https://cache.example.com", { delay: 1, env: env() });
    assert.equal(token, `stub.${Buffer.from("https://cache.example.com").toString("base64url")}.1`);
  });

  it("idToken explains a missing id-token permission", async () => {
    await assert.rejects(idToken("https://cache.example.com", { env: {} }), /id-token: write/);
  });

  it("idToken doesn't retry 4xx", async () => {
    const bad = { ...env(), ACTIONS_ID_TOKEN_REQUEST_TOKEN: "wrong" };
    await assert.rejects(idToken("https://cache.example.com", { delay: 1, env: bad }), /failed: 401/);
  });

  it("whoami returns the subject", async () => {
    const token = await idToken("https://cache.example.com", { env: env() });
    assert.equal(await whoami(new URL(stub.url), token), "repo:example-org/app:ref:refs/heads/main");
  });

  it("whoami explains a wrong audience", async () => {
    const token = await idToken("https://other.example.com", { env: env() });
    await assert.rejects(whoami(new URL(stub.url), token), /401 \(invalid OIDC token: aud doesn't match CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE\): the cache rejected/);
  });

  it("whoami is skipped for a cache without the endpoint", async () => {
    const server = createServer((_, res) => res.writeHead(404).end());
    await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
    const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
    try {
      assert.equal(await whoami(new URL(`http://127.0.0.1:${port}`), "x"), undefined);
    } finally {
      server.close();
    }
  });
});
