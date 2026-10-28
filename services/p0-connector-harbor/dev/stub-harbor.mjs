// A stand-in for Harbor over https, with a stand-in OpenID provider beside
// it, for running the connector locally. The provider's issuer is
// https://localhost:<port>/idp: it serves its discovery document, and mints a
// fixed, fake ID token for the refresh token stub-secrets.mjs stores. Harbor
// answers GET /api/v2.0/systeminfo the way Harbor v2.14.0 does: in full for
// that token, and with the public fields only, still a 200, for anyone else.
// Set HARBOR_STUB_VERSION=v2.12.0-9da38ae0 to copy v2.12.x, where the version
// is public. It answers what install validation reads the way Harbor answers
// an administrator: /users/current with sysadmin_flag set. It also answers
// the user list (one user) and the project list (library), and 401 for
// anyone else on all but the project list.
//
// It needs a certificate. Make one in a directory of your own, outside the
// repository:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 7 \
//     -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
// Then run it with that directory, and give the connector the certificate:
//   HARBOR_STUB_CERT_DIR=<dir> node stub-harbor.mjs
//   NODE_EXTRA_CA_CERTS=<dir>/cert.pem ...
//
// Every credential here is fake.
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

const certDir = process.env.HARBOR_STUB_CERT_DIR;
if (!certDir) {
  console.error(
    "Set HARBOR_STUB_CERT_DIR to the directory with key.pem and cert.pem."
  );
  process.exit(1);
}
const PORT = Number(process.env.HARBOR_STUB_PORT ?? 8443);
const VERSION = process.env.HARBOR_STUB_VERSION ?? "v2.14.0-44a74424";
const VERSION_IS_PUBLIC = VERSION.startsWith("v2.12.");
const ISSUER = `https://localhost:${PORT}/idp`;
// The refresh token stub-secrets.mjs stores, and the ID token minted for it:
// three base64url parts, as a JWS has. Neither is real.
const REFRESH_TOKEN = "fake-refresh-token";
const ID_TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdHViIn0.ZmFrZQ";
const BEARER = `Bearer ${ID_TOKEN}`;

const reply = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
};

https
  .createServer(
    {
      key: fs.readFileSync(path.join(certDir, "key.pem")),
      cert: fs.readFileSync(path.join(certDir, "cert.pem")),
    },
    (req, res) => {
      const route = new URL(req.url ?? "/", "https://localhost").pathname;
      const admin = req.headers.authorization === BEARER;
      const unauthorized = () =>
        reply(res, 401, {
          errors: [{ code: "UNAUTHORIZED", message: "unauthorized" }],
        });
      if (route === "/idp/.well-known/openid-configuration") {
        return reply(res, 200, {
          issuer: ISSUER,
          token_endpoint: `${ISSUER}/token`,
          token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
          ],
        });
      }
      if (route === "/idp/token" && req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          const form = new URLSearchParams(body);
          if (form.get("refresh_token") !== REFRESH_TOKEN) {
            return reply(res, 400, { error: "invalid_grant" });
          }
          reply(res, 200, {
            access_token: "fake-access-token",
            id_token: ID_TOKEN,
            token_type: "Bearer",
            expires_in: 3600,
          });
        });
        return;
      }
      if (route === "/api/v2.0/users") {
        return admin
          ? reply(res, 200, [
              {
                user_id: 3,
                username: "someone",
                email: "someone@example.com",
                sysadmin_flag: false,
                admin_role_in_auth: false,
              },
            ])
          : unauthorized();
      }
      if (route === "/api/v2.0/users/current") {
        return admin
          ? reply(res, 200, {
              user_id: 9000,
              username: "harbor-automation",
              email: "harbor-automation@example.com",
              sysadmin_flag: true,
              admin_role_in_auth: false,
            })
          : unauthorized();
      }
      if (route === "/api/v2.0/projects") {
        return reply(res, 200, [{ project_id: 1, name: "library" }]);
      }
      if (route !== "/api/v2.0/systeminfo") {
        return reply(res, 404, {
          errors: [{ code: "NOT_FOUND", message: "stub: no such route" }],
        });
      }
      const anonymous = {
        auth_mode: "oidc_auth",
        primary_auth_mode: false,
        self_registration: false,
        banner_message: "",
        oidc_provider_name: "google",
        ...(VERSION_IS_PUBLIC ? { harbor_version: VERSION } : {}),
      };
      if (!admin) return reply(res, 200, anonymous);
      reply(res, 200, {
        ...anonymous,
        harbor_version: VERSION,
        current_time: new Date().toISOString(),
        external_url: `https://localhost:${PORT}`,
        registry_url: `localhost:${PORT}`,
        has_ca_root: false,
        project_creation_restriction: "adminonly",
        read_only: false,
        registry_storage_provider_name: "",
        notification_enable: true,
      });
    }
  )
  .listen(PORT, "127.0.0.1", () =>
    console.log(`stub Harbor on https://localhost:${PORT}`)
  );
