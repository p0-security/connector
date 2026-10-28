// A stand-in for AWS Secrets Manager, for running the connector locally. It
// answers GetSecretValue only. Point the connector at it with:
//   AWS_ENDPOINT_URL_SECRETS_MANAGER=http://127.0.0.1:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
//
// `harbor-admin` holds the admin credential whose refresh token
// stub-harbor.mjs's provider accepts, and `harbor-admin-stale` one it refuses
// (invalid_grant). `denied` is refused, and any other name isn't found. Every
// credential here is fake. The issuer is stub-harbor.mjs's, on its default
// port.
import http from "node:http";

const ADMIN = {
  issuer: "https://localhost:8443/idp",
  clientId: "harbor",
  clientSecret: "fake-client-secret",
  refreshToken: "fake-refresh-token",
};

const SECRETS = {
  "harbor-admin": ADMIN,
  "harbor-admin-stale": { ...ADMIN, refreshToken: "fake-revoked-token" },
};

const reply = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/x-amz-json-1.1" });
  res.end(JSON.stringify(body));
};

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const target = req.headers["x-amz-target"];
      if (target !== "secretsmanager.GetSecretValue") {
        return reply(res, 400, {
          __type: "InvalidRequestException",
          message: `stub: unsupported ${target}`,
        });
      }
      const { SecretId } = JSON.parse(body || "{}");
      if (SecretId === "denied") {
        return reply(res, 400, {
          __type: "AccessDeniedException",
          message: "stub: denied",
        });
      }
      const secret = SECRETS[SecretId];
      if (!secret) {
        return reply(res, 400, {
          __type: "ResourceNotFoundException",
          message: "stub: no such secret",
        });
      }
      reply(res, 200, {
        ARN: `arn:aws:secretsmanager:us-west-2:000000000000:secret:${SecretId}-abcdef`,
        Name: SecretId,
        VersionId: "00000000-0000-4000-8000-000000000000",
        SecretString: JSON.stringify(secret),
        VersionStages: ["AWSCURRENT"],
        CreatedDate: 1760000000,
      });
    });
  })
  .listen(4566, "127.0.0.1", () =>
    console.log("stub Secrets Manager on http://127.0.0.1:4566")
  );
