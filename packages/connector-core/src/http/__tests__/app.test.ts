import { Router } from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createExpressApp } from "../app.ts";
import { bearerAuthzMiddleware } from "../middlewares/bearer.ts";

const TOKEN = "good-token";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const trpc = Router();
  trpc.get("/app.metadata.get", (_req, res) => {
    res.status(200).json({ ok: true });
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
