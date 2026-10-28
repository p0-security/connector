import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  connectorError,
  logger,
  propertySeed,
  seededRandom,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  installedState,
  newFakeArgoCd,
} from "../../../argocd/__tests__/fake-argocd.ts";
import { buildLine } from "../../../argocd/policy.ts";
import { argoCdRefusalReason } from "../../../refusals.ts";
import {
  PARSED_INSTANCE,
  PATTERN,
  connectWith,
  patches,
  userBodyOf,
} from "../../__tests__/helpers.ts";
import { newGlobalRolePrimitives } from "../handler.ts";

beforeEach(() => {
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

/** A value's non-blank lines, trimmed, as Argo CD would read them. */
const linesOf = (value: string | undefined) =>
  (value ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");

// Grants and revokes of random roles for random emails, against random
// policies: most emails and roles are near misses of what P0 writes, and
// some policies hold lines Argo CD refuses, or the grant already. Whatever
// happens, the connector writes policy.p0.csv alone, writes only P0's own
// line, refuses only with a reason from the closed set, and a revoke takes
// back exactly what the grant added.
describe("global role grants and revokes, over random inputs", () => {
  const seed = propertySeed();

  it(
    `touch policy.p0.csv alone, and revoke what they grant (PROPERTY_SEED=${seed})`,
    { timeout: 60_000 },
    async () => {
      const random = seededRandom(seed);
      const pick = <T>(items: readonly T[]): T => {
        const item = items[Math.floor(random() * items.length)];
        if (item === undefined) throw new Error("picked from no items");
        return item;
      };
      const EMAILS = [
        "alice@example.com",
        "Alice@Example.COM",
        "bob@example.com",
        "mallory@evil.io",
        "alice smith@example.com",
        "alice,x@example.com",
        "alice#@example.com",
        "@example.com",
        "p0-connector@example.com",
      ];
      const ROLES = [
        "role:dev",
        "role:ops",
        "role:readonly",
        "role:admin",
        "role:p0-connector",
        "role:nobody",
        "role:lead",
      ];
      const CUSTOMER_LINES = [
        "p, role:dev, applications, get, */*, allow",
        "p, role:ops, applications, sync, */*, allow",
        "g, role:lead, role:dev",
        "g, alice@example.com, role:ops",
        "g, bob@example.com, role:dev",
        "# a comment",
        "",
        "nonsense",
      ];
      const P0_LINES = [
        "g, bob@example.com, role:dev",
        "g, alice@example.com, role:readonly",
        "  g, alice@example.com, role:dev ",
        "",
      ];
      const lines = (from: readonly string[], most: number) =>
        Array.from({ length: Math.floor(random() * most) }, () => pick(from));

      for (let i = 0; i < 400; i++) {
        const customer = `${lines(CUSTOMER_LINES, 5).join("\n")}\n`;
        const hasP0Key = random() < 0.6;
        const p0 = lines(P0_LINES, 3).join("\n");
        const data: Record<string, string> = {
          "policy.csv": customer,
          ...(random() < 0.2 ? { "policy.default": pick(ROLES) } : {}),
          ...(hasP0Key ? { "policy.p0.csv": p0 } : {}),
        };
        const before = { ...data };
        const argocd = newFakeArgoCd(
          installedState({ rbac: { namespace: "argocd", data } })
        );
        const email = pick(EMAILS);
        const role = pick(ROLES);
        const context = { ...PARSED_INSTANCE, requestId: `req-${i}`, role };
        const access = newGlobalRolePrimitives(logger, connectWith());
        const where = JSON.stringify({ seed, i, email, role, before });

        let granted = false;
        try {
          await access.setPoliciesForUser(context, email, userBodyOf(email), [
            { role },
          ]);
          granted = true;
        } catch (error) {
          if (!(error instanceof ConnectorError)) throw error;
          expect(error.data.type, where).toBe("validation_error");
          expect(
            argoCdRefusalReason.safeParse(error.data.payload.reason).success,
            where
          ).toBe(true);
        }

        const after = argocd.state.rbac.data ?? {};
        // Only policy.p0.csv ever changes.
        const { "policy.p0.csv": p0After, ...othersAfter } = after;
        const { "policy.p0.csv": p0Before, ...othersBefore } = before;
        expect(othersAfter, where).toEqual(othersBefore);
        for (const patch of patches(argocd)) {
          expect(Object.keys((patch as { data: object }).data), where).toEqual([
            "policy.p0.csv",
          ]);
        }
        const added = linesOf(p0After).filter(
          (line) => !linesOf(p0Before).includes(line)
        );
        if (granted) {
          const line = buildLine(email, { kind: "global", role });
          expect(linesOf(p0After), where).toContain(line);
          // Nothing but P0's own line, and never one for the connector.
          expect(
            added.every((text) => text === line),
            where
          ).toBe(true);
          expect(line, where).not.toContain("p0-connector,");
          expect(line.endsWith("role:p0-connector"), where).toBe(false);
        } else {
          expect(p0After, where).toBe(p0Before);
        }

        await access.setPoliciesForUser(context, email, userBodyOf(email), [
          { role: null },
        ]);
        const revoked = argocd.state.rbac.data ?? {};
        const { "policy.p0.csv": p0Revoked, ...othersRevoked } = revoked;
        expect(othersRevoked, where).toEqual(othersBefore);
        let line: string | undefined;
        try {
          line = buildLine(email, { kind: "global", role });
        } catch {
          line = undefined;
        }
        if (line !== undefined) {
          expect(linesOf(p0Revoked), where).not.toContain(line);
          // Every other line P0's key held is still there.
          expect(linesOf(p0Revoked), where).toEqual(
            linesOf(p0Before).filter((text) => text !== line)
          );
        } else {
          expect(p0Revoked, where).toBe(p0Before);
        }
        vi.unstubAllGlobals();
      }
    }
  );
});

// The refusals that come before Argo CD is called are pure functions of the
// email, the role and the pattern, so they are checked here against the
// rules themselves.
describe("a grant's early refusals, over random emails", () => {
  const seed = propertySeed();

  it(`refuse without calling Argo CD exactly the emails the allowlist or the line refuses (PROPERTY_SEED=${seed})`, async () => {
    const random = seededRandom(seed);
    const ALPHABET = [
      "a",
      "@",
      ".",
      "-",
      "e",
      "x",
      "m",
      "p",
      "l",
      ",",
      " ",
      "#",
      "A",
    ];
    for (let i = 0; i < 500; i++) {
      const local = Array.from(
        { length: 1 + Math.floor(random() * 6) },
        () => ALPHABET[Math.floor(random() * ALPHABET.length)]
      ).join("");
      const email =
        random() < 0.7 ? `${local}@example.com` : `${local}@evil.io`;
      const argocd = newFakeArgoCd(installedState());
      const connect = connectWith();
      const access = newGlobalRolePrimitives(logger, connect);
      const context = { ...PARSED_INSTANCE, requestId: "r", role: "role:dev" };
      const where = JSON.stringify({ seed, i, email });

      let lineOk = true;
      try {
        buildLine(email, { kind: "global", role: "role:dev" });
      } catch {
        lineOk = false;
      }
      const parts = email.split("@");
      const domainOk =
        parts.length === 2 && parts[0] !== "" && parts[1] === "example.com";

      if (domainOk && lineOk) {
        await access.setPoliciesForUser(context, email, userBodyOf(email), [
          { role: "role:dev" },
        ]);
        expect(connect, where).toHaveBeenCalled();
      } else {
        const { data } = await connectorError(() =>
          access.setPoliciesForUser(context, email, userBodyOf(email), [
            { role: "role:dev" },
          ])
        );
        expect(data.payload.reason, where).toBe(
          domainOk ? "not_an_email" : "domain_not_allowed"
        );
        expect(connect, where).not.toHaveBeenCalled();
        expect(argocd.fetch, where).not.toHaveBeenCalled();
      }
      vi.unstubAllGlobals();
    }
  });
});
