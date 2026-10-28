import { ConnectorError } from "@p0security/connector-core";
import { generateKeyPairSync, verify } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  mintUserToken,
  newProvisionerClient,
  signAssertion,
} from "../client.ts";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const signingKey = privateKey.export({
  type: "pkcs8",
  format: "pem",
}) as string;

const jwtBearer = {
  domain: "acme.service-now.com",
  clientId: "jwt-client",
  clientSecret: "jwt-secret",
  signingKey,
  keyId: "p0-key",
};

const decode = (part: string) =>
  JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

describe("signAssertion", () => {
  it("signs a JWT whose issuer and audience are the client ID", () => {
    const jwt = signAssertion(jwtBearer, "p0-agent-abc", 1_000);
    const [header, claims, signature] = jwt.split(".");

    expect(decode(header)).toEqual({ alg: "RS256", typ: "JWT", kid: "p0-key" });
    expect(decode(claims)).toMatchObject({
      iss: "jwt-client",
      aud: "jwt-client",
      sub: "p0-agent-abc",
      iat: 1_000,
      exp: 1_300,
    });
    expect(decode(claims).jti).toEqual(expect.any(String));
    expect(
      verify(
        "RSA-SHA256",
        Buffer.from(`${header}.${claims}`),
        publicKey,
        Buffer.from(signature, "base64url")
      )
    ).toBe(true);
  });

  it("gives each JWT its own jti", () => {
    const jti = () =>
      decode(signAssertion(jwtBearer, "p0-agent-abc").split(".")[1]).jti;
    expect(jti()).not.toEqual(jti());
  });
});

describe("mintUserToken", () => {
  it("sends the JWT bearer grant with the client secret", async () => {
    fetchMock.mockResolvedValue(json(200, { access_token: "user-token" }));

    await expect(mintUserToken(jwtBearer, "p0-agent-abc")).resolves.toBe(
      "user-token"
    );
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://acme.service-now.com/oauth_token.do");
    const body = new URLSearchParams(init?.body as URLSearchParams);
    expect(body.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    expect(body.get("client_id")).toBe("jwt-client");
    expect(body.get("client_secret")).toBe("jwt-secret");
    expect(decode(body.get("assertion")!.split(".")[1]).sub).toBe(
      "p0-agent-abc"
    );
  });

  it("gives ServiceNow's reason when it refuses the exchange", async () => {
    fetchMock.mockResolvedValue(
      json(400, { error: "invalid_grant", error_description: "User not found" })
    );

    const error = await mintUserToken(jwtBearer, "p0-agent-abc").catch(
      (e: unknown) => e
    );
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as Error).message).toContain("User not found");
  });
});

describe("newProvisionerClient", () => {
  const login = () =>
    fetchMock.mockResolvedValueOnce(json(200, { access_token: "prov-token" }));

  const newClient = () =>
    newProvisionerClient({
      domain: "acme.service-now.com",
      clientId: "prov-client",
      clientSecret: "prov-secret",
    });

  it("logs in with client credentials and calls the Table API with the token", async () => {
    login();
    fetchMock.mockResolvedValueOnce(
      json(200, {
        result: [{ sys_id: "a".repeat(32), user_name: "p0-agent-abc" }],
      })
    );

    const client = await newClient();
    await expect(client.findUser("p0-agent-abc")).resolves.toEqual({
      sysId: "a".repeat(32),
      userName: "p0-agent-abc",
    });

    const loginBody = new URLSearchParams(
      fetchMock.mock.calls[0][1]?.body as URLSearchParams
    );
    expect(loginBody.get("grant_type")).toBe("client_credentials");
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain(
      "https://acme.service-now.com/api/now/table/sys_user?"
    );
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- copied from perim as-is; preserve its stringification
    expect(decodeURIComponent(String(url))).toContain(
      "sysparm_query=user_name=p0-agent-abc"
    );
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      "Bearer prov-token"
    );
  });

  it("creates a machine user with web service access only", async () => {
    login();
    fetchMock.mockResolvedValueOnce(
      json(201, { result: { sys_id: "b".repeat(32) } })
    );

    const client = await newClient();
    await expect(client.createUser("p0-agent-abc")).resolves.toBe(
      "b".repeat(32)
    );
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- copied from perim as-is; preserve its stringification
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toMatchObject({
      user_name: "p0-agent-abc",
      identity_type: "machine",
      web_service_access_only: true,
      active: true,
    });
  });

  it("reads a role row that ServiceNow kept without its role as an empty name", async () => {
    login();
    fetchMock.mockResolvedValueOnce(
      json(200, {
        result: [
          { sys_id: "r1", "role.name": "itil" },
          { sys_id: "r2", "role.name": "" },
        ],
      })
    );

    const client = await newClient();
    await expect(client.userRoles("b".repeat(32))).resolves.toEqual([
      { rowId: "r1", roleName: "itil" },
      { rowId: "r2", roleName: "" },
    ]);
  });

  it("refuses a role that the instance does not have", async () => {
    login();
    fetchMock.mockResolvedValueOnce(json(200, { result: [] }));

    const client = await newClient();
    await expect(client.addRole("b".repeat(32), "nope")).rejects.toThrow(
      'ServiceNow has no role "nope"'
    );
  });

  it("treats a user that is already gone as deleted", async () => {
    login();
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 404 }));

    const client = await newClient();
    await expect(client.deleteUser("b".repeat(32))).resolves.toBeUndefined();
  });

  it("gives ServiceNow's reason when the Table API refuses a call", async () => {
    login();
    fetchMock.mockResolvedValueOnce(
      json(403, {
        error: {
          message: "User Not Authorized",
          detail: "Access to unscoped api is not allowed",
        },
      })
    );

    const client = await newClient();
    await expect(client.findUser("p0-agent-abc")).rejects.toThrow(
      "Access to unscoped api is not allowed"
    );
  });
});
