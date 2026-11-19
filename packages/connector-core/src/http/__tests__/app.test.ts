import { Router } from "express";
import type { Server } from "node:http";
import { type AddressInfo, Server as NetServer } from "node:net";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { JSON_BODY_LIMIT, createExpressApp, runExpressApp } from "../app.ts";
import { bearerAuthzMiddleware } from "../middlewares/bearer.ts";

const TOKEN = "good-token";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const trpc = Router();
  trpc.get("/app.metadata.get", (_req, res) => {
    res.status(200).json({ ok: true });
  });
  trpc.post("/src.logs.read", (req, res) => {
    const body = req.body as { query?: { permissions?: string[] } };
    res.status(200).json({ permissions: body.query?.permissions?.length });
  });

  const app = createExpressApp("test-module", { "/trpc": trpc }, [
    bearerAuthzMiddleware(async (token) => token === TOKEN),
  ]);

  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe("GET /health", () => {
  it("answers 200 with the module name and no Authorization header", async () => {
    const response = await fetch(`${baseUrl}/health`);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ module: "test-module" });
  });

  it("answers HEAD without a token", async () => {
    const response = await fetch(`${baseUrl}/health`, { method: "HEAD" });

    expect(response.status).toBe(200);
  });

  it("does not open other methods on the same path", async () => {
    const response = await fetch(`${baseUrl}/health`, { method: "POST" });

    expect(response.status).toBe(403);
  });
});

describe("routes behind the bearer middleware", () => {
  it("refuses /trpc without an Authorization header", async () => {
    const response = await fetch(`${baseUrl}/trpc/app.metadata.get`);

    expect(response.status).toBe(403);
  });

  it("refuses an unknown path without an Authorization header", async () => {
    const response = await fetch(`${baseUrl}/healthz`);

    expect(response.status).toBe(403);
  });

  it("admits /trpc with a token the middleware accepts", async () => {
    const response = await fetch(`${baseUrl}/trpc/app.metadata.get`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });

    expect(response.status).toBe(200);
  });
});

describe("JSON bodies", () => {
  const post = (body: string) =>
    fetch(`${baseUrl}/trpc/src.logs.read`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body,
    });

  it("accepts a logs read whose permission list is past Express's 100 KB default", async () => {
    const permissions = Array.from(
      { length: 4_000 },
      (_, i) => `service.resources.permission${String(i).padStart(5, "0")}`
    );
    const body = JSON.stringify({ query: { permissions } });
    expect(body.length).toBeGreaterThan(100 * 1024);

    const response = await post(body);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ permissions: 4_000 });
  });

  it(`answers 413 for a body over ${JSON_BODY_LIMIT}`, async () => {
    const response = await post(
      JSON.stringify({ padding: "x".repeat(6 * 1024 * 1024) })
    );

    expect(response.status).toBe(413);
  });
});

describe("runExpressApp", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  /** Runs the app and returns the arguments it would pass to `listen`. */
  const listenArgs = (host?: string) => {
    const listen = vi
      .spyOn(NetServer.prototype, "listen")
      .mockImplementation(function (this: NetServer) {
        return this;
      });
    runExpressApp("test-module", {}, [], host);
    return listen.mock.calls[0];
  };

  it("listens on every interface without a host", () => {
    vi.stubEnv("PORT", undefined);

    expect(listenArgs()).toEqual([8080, expect.any(Function)]);
  });

  it("listens only on the host given", () => {
    vi.stubEnv("PORT", "9090");

    expect(listenArgs("127.0.0.1")).toEqual([
      9090,
      "127.0.0.1",
      expect.any(Function),
    ]);
  });
});
