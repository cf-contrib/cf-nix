// @ts-check
// Stands in for both the runner's OIDC endpoint and the cache's /v1/whoami.
// Tokens are `stub.<base64url audience>.<n>`, so tests can tell refreshed
// tokens apart and the cache can reject a wrong audience.
// Run directly (smoke test) or import startStub() (unit tests).
import { createServer } from "node:http";

/** @param {{ port?: number, audience?: string, failures?: number }} [options] */
export function startStub({ port = 0, audience, failures = 0 } = {}) {
  let issued = 0;
  let failuresLeft = failures;

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://stub");
    const json = (/** @type {number} */ status, /** @type {unknown} */ body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (url.pathname === "/oidc") {
      if (req.headers.authorization !== "bearer stub-request-token") return json(401, {});
      if (failuresLeft > 0) {
        failuresLeft--;
        return json(500, {});
      }
      issued++;
      const aud = Buffer.from(url.searchParams.get("audience") ?? "").toString("base64url");
      return json(200, { value: `stub.${aud}.${issued}` });
    }

    if (url.pathname === "/v1/whoami") {
      const header = req.headers.authorization ?? "";
      const [user, token = ""] = Buffer.from(header.replace(/^Basic /, ""), "base64").toString().split(":");
      const [, aud = ""] = token.split(".");
      const expected = audience ?? `http://${req.headers.host}`;
      if (user !== "actions" || Buffer.from(aud, "base64url").toString() !== expected) {
        return json(401, {
          error: "unauthorized",
          message: "invalid OIDC token: aud doesn't match CF_NIX_WORKER_GITHUB_OIDC_AUDIENCE",
        });
      }
      return json(200, { kind: "actions", subject: "repo:example-org/app:ref:refs/heads/main", rule: 0 });
    }

    res.writeHead(404).end();
  });

  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const address = /** @type {import("node:net").AddressInfo} */ (server.address());
      resolve({ server, url: `http://127.0.0.1:${address.port}`, issued: () => issued });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { url } = await startStub({ port: Number(process.env.PORT ?? 8787) });
  console.log(`stub listening on ${url}`);
}
