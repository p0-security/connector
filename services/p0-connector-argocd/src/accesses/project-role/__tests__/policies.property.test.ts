import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
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
import { newProjectRolePrimitives } from "../handler.ts";

beforeEach(() => {
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const linesOf = (value: string | undefined) =>
  (value ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");

// As the global role's property test, for project roles: random projects,
// roles and groups, some of them the email, against random policies.
describe("project role grants and revokes, over random inputs", () => {
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
        "bob@example.com",
        "x y@example.com",
      ];
      const PROJECTS = ["payments", "billing", "default"];
      const ROLES = ["deployer", "viewer", "admin"];
      const POLICY_LINES = [
        "g, alice@example.com, proj:payments:deployer",
        "g, role:lead, proj:billing:viewer",
        "g, bob@example.com, role:lead",
        "p, proj:payments:viewer, applications, get, payments/*, allow",
        "nonsense",
        "",
      ];
      const P0_LINES = [
        "g, alice@example.com, proj:payments:viewer",
        "g, bob@example.com, proj:billing:admin",
        "",
      ];
      const some = (from: readonly string[], most: number) =>
        Array.from({ length: Math.floor(random() * most) }, () => pick(from));

      for (let i = 0; i < 300; i++) {
        const data: Record<string, string> = {
          "policy.csv": `${some(POLICY_LINES, 4).join("\n")}\n`,
          ...(random() < 0.6
            ? { "policy.p0.csv": some(P0_LINES, 3).join("\n") }
            : {}),
        };
        const before = { ...data };
        const projects = PROJECTS.filter(() => random() < 0.7).map((name) => ({
          name,
          roles: ROLES.filter(() => random() < 0.6).map((role) => ({
            name: role,
            groups: some(["alice@example.com", "team"], 2),
          })),
        }));
        const argocd = newFakeArgoCd(
          installedState({ rbac: { namespace: "argocd", data }, projects })
        );
        const email = pick(EMAILS);
        const project = pick(PROJECTS);
        const role = pick(ROLES);
        const context = {
          ...PARSED_INSTANCE,
          requestId: `req-${i}`,
          project,
          role,
        };
        const access = newProjectRolePrimitives(logger, connectWith());
        const where = JSON.stringify({ seed, i, email, project, role, before });
        const grant = { kind: "project", project, role } as const;

        let granted = false;
        try {
          await access.setPoliciesForUser(context, email, userBodyOf(email), [
            { project, role },
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

        const { "policy.p0.csv": p0Before, ...othersBefore } = before;
        const { "policy.p0.csv": p0After, ...othersAfter } =
          argocd.state.rbac.data ?? {};
        expect(othersAfter, where).toEqual(othersBefore);
        for (const patch of patches(argocd)) {
          expect(Object.keys((patch as { data: object }).data), where).toEqual([
            "policy.p0.csv",
          ]);
        }
        let line: string | undefined;
        try {
          line = buildLine(email, grant);
        } catch {
          line = undefined;
        }
        if (granted) {
          expect(line, where).toBeDefined();
          const added = linesOf(p0After).filter(
            (text) => !linesOf(p0Before).includes(text)
          );
          expect(
            added.every((text) => text === line),
            where
          ).toBe(true);
          expect(linesOf(p0After), where).toContain(line);
        } else {
          expect(p0After, where).toBe(p0Before);
        }

        await access.setPoliciesForUser(context, email, userBodyOf(email), [
          { project, role: null },
        ]);
        const { "policy.p0.csv": p0Revoked, ...othersRevoked } =
          argocd.state.rbac.data ?? {};
        expect(othersRevoked, where).toEqual(othersBefore);
        if (line !== undefined) {
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
