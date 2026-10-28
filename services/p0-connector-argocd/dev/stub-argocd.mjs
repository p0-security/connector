// copy of services/p0-connector-harbor/dev/stub-harbor.mjs, standing in for
// Argo CD instead of Harbor
//
// A stand-in for Argo CD's API over https, for running the connector
// locally. It answers what the connector calls the way Argo CD v3.5.5 does
// (read from its source, not checked on a live instance) for an install
// that followed the steps: `platform/argocd` manages `argocd/argocd-rbac-cm`,
// and the p0-connector account may get that Application, patch that
// ConfigMap through it, and get projects, and nothing else.
//
// - GET /api/version answers anyone: `Version` alone to an anonymous caller.
// - GET /api/v1/session/userinfo answers anyone: `{}` for a token it doesn't
//   take, since the gateway leaves out an `omitempty` `loggedIn: false`.
// - GET /api/v1/account/can-i/... answers "no" to all but `projects get`.
// - GET /api/v1/applications/argocd, and 403 for any other Application.
// - GET and POST /api/v1/applications/argocd/resource for argocd-rbac-cm.
//   POST takes a merge patch as a JSON string, and keeps it in memory.
// - GET /api/v1/projects lists `default`.
// Anything else under /api/v1 is a 401 without the token.
//
// Set ARGOCD_STUB_VERSION=v2.14.11+8283115 to copy an Argo CD the connector
// doesn't support.
//
// It needs a certificate. Make one in a directory of your own, outside the
// repository:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 7 \
//     -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
// Then run it with that directory, and give the connector the certificate:
//   ARGOCD_STUB_CERT_DIR=<dir> node stub-argocd.mjs
//   NODE_EXTRA_CA_CERTS=<dir>/cert.pem ...
//
// The token is fake: stub-secrets.mjs's `argocd-token` holds it.
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

const certDir = process.env.ARGOCD_STUB_CERT_DIR;
if (!certDir) {
  console.error(
    "Set ARGOCD_STUB_CERT_DIR to the directory with key.pem and cert.pem."
  );
  process.exit(1);
}
const PORT = Number(process.env.ARGOCD_STUB_PORT ?? 8443);
const VERSION = process.env.ARGOCD_STUB_VERSION ?? "v3.5.5+2f9b0d1";
const BEARER = "Bearer fake-argocd-api-token";
const RBAC_QUERY = {
  namespace: "argocd",
  resourceName: "argocd-rbac-cm",
  version: "v1",
  kind: "ConfigMap",
  group: "",
};

const rbacData = {
  "policy.csv": [
    "p, role:p0-connector, applications, get, platform/argocd, allow",
    "p, role:p0-connector, applications, update//ConfigMap/argocd/argocd-rbac-cm, platform/argocd, allow",
    "p, role:p0-connector, projects, get, *, allow",
    "g, p0-connector, role:p0-connector",
    "",
  ].join("\n"),
  scopes: "[groups, email]",
};

const reply = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};

// grpc-gateway's error body.
const grpcError = (res, status, code, message) =>
  reply(res, status, { error: message, code, message });

const namesRbac = (query) =>
  Object.entries(RBAC_QUERY).every(([key, value]) => query.get(key) === value);

https
  .createServer(
    {
      key: fs.readFileSync(path.join(certDir, "key.pem")),
      cert: fs.readFileSync(path.join(certDir, "cert.pem")),
    },
    (req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const url = new URL(req.url ?? "/", "https://localhost");
        const route = url.pathname;
        const authorized = req.headers.authorization === BEARER;

        if (route === "/api/version") {
          return reply(
            res,
            200,
            authorized
              ? { Version: VERSION, Platform: "linux/amd64" }
              : { Version: VERSION }
          );
        }
        if (route === "/api/v1/session/userinfo") {
          return reply(
            res,
            200,
            authorized
              ? { loggedIn: true, username: "p0-connector", iss: "argocd" }
              : {}
          );
        }
        if (!route.startsWith("/api/v1/")) {
          return grpcError(res, 404, 5, "stub: no such route");
        }
        if (!authorized) {
          return grpcError(res, 401, 16, "invalid session");
        }
        if (route.startsWith("/api/v1/account/can-i/")) {
          const yes = route === "/api/v1/account/can-i/projects/get/*";
          return reply(res, 200, { value: yes ? "yes" : "no" });
        }
        if (route === "/api/v1/projects") {
          return reply(res, 200, {
            metadata: {},
            items: [{ metadata: { name: "default" }, spec: {} }],
          });
        }
        if (route === "/api/v1/applications/argocd" && req.method === "GET") {
          return reply(res, 200, {
            metadata: { name: "argocd", namespace: "argocd" },
            spec: { project: "platform" },
            status: {
              resources: [
                {
                  version: "v1",
                  kind: "ConfigMap",
                  namespace: "argocd",
                  name: "argocd-rbac-cm",
                },
              ],
            },
          });
        }
        if (route === "/api/v1/applications/argocd/resource") {
          if (!namesRbac(url.searchParams)) {
            return grpcError(res, 400, 3, "stub: not part of the application");
          }
          if (req.method === "GET") {
            return reply(res, 200, {
              manifest: JSON.stringify({
                apiVersion: "v1",
                kind: "ConfigMap",
                metadata: { name: "argocd-rbac-cm", namespace: "argocd" },
                data: rbacData,
              }),
            });
          }
          if (req.method === "POST") {
            if (
              url.searchParams.get("patchType") !==
              "application/merge-patch+json"
            ) {
              return grpcError(res, 400, 3, "stub: unsupported patch type");
            }
            try {
              const patch = JSON.parse(JSON.parse(body));
              for (const [key, value] of Object.entries(patch.data ?? {})) {
                if (value === null) delete rbacData[key];
                else rbacData[key] = String(value);
              }
            } catch {
              return grpcError(
                res,
                400,
                3,
                "stub: the body isn't a patch string"
              );
            }
            return reply(res, 200, { manifest: "{}" });
          }
        }
        if (route.startsWith("/api/v1/applications/")) {
          return grpcError(res, 403, 7, "permission denied");
        }
        grpcError(res, 404, 5, "stub: no such route");
      });
    }
  )
  .listen(PORT, "127.0.0.1", () =>
    console.log(`stub Argo CD on https://localhost:${PORT}`)
  );
