import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretRef,
  SecretVersionRef,
} from "@p0security/connector-secret-manager-client";
import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";

import { fetchAdminKey, setGrantSecret } from "../secrets.ts";
import {
  type Random,
  anyString,
  fileSeed,
  forAll,
  mutateJson,
} from "./generate.ts";

const SEED = fileSeed();
const RUNS = 1000;
const TIMEOUT = 30_000;

// Every generated key field starts with this, so a test can tell whether any
// part of a key reached an error.
const CANARY = "CANARY";

const KEY_FIELDS = ["client_id", "client_secret", "apiKey", "id"];

const ALPHANUMERIC = [
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
];

// Half of them letters and digits only, which the connector stores.
const keyField = (random: Random) =>
  `${CANARY}${
    random.chance(0.6)
      ? random.string(ALPHANUMERIC, random.int(0, 12))
      : anyString(random)
  }`;

const VERSION = {
  ref: "p0_grant/versions/1" as SecretVersionRef,
  secretRef: "p0_grant" as SecretRef,
  state: "enabled" as const,
  createTime: new Date(0),
};

const rendered = (error: unknown) =>
  `${inspect(error, { depth: Infinity, showHidden: true })}\n${JSON.stringify(
    error instanceof ConnectorError ? error.data : error
  )}`;

/** What the Admin key secret might hold: the key, the key a little broken,
 * something else as JSON, text, or bytes. */
const generateStoredKey = (random: Random): Buffer | string => {
  const json = JSON.stringify(
    mutateJson(
      random,
      { client_id: keyField(random), client_secret: keyField(random) },
      KEY_FIELDS
    )
  );
  switch (random.int(0, 5)) {
    case 0:
      return Buffer.from(json);
    case 1:
      return `${keyField(random)}:${keyField(random)}`;
    case 2:
      return Buffer.from(
        Array.from({ length: random.int(0, 24) }, () => random.int(0, 255))
      );
    default:
      return json;
  }
};

/** The rule for the Admin key secret, stated without zod: JSON for an object
 * whose `client_id` and `client_secret` are non-empty strings. */
const expectedAdminKey = (stored: Buffer | string) => {
  let value: unknown;
  try {
    value = JSON.parse(
      typeof stored === "string" ? stored : stored.toString("utf8")
    );
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  const { client_id, client_secret } = value as Record<string, unknown>;
  return typeof client_id === "string" &&
    client_id.length > 0 &&
    typeof client_secret === "string" &&
    client_secret.length > 0
    ? { client_id, client_secret }
    : undefined;
};

describe("fetchAdminKey, on generated secret values", () => {
  it(
    "returns exactly the key the rule allows, and otherwise a validation error that quotes none of it",
    async () => {
      const counts = await forAll(
        SEED,
        RUNS,
        generateStoredKey,
        async (stored) => {
          const secrets = {
            getSecretValue: vi.fn(async () => ({
              value: stored,
              version: VERSION,
            })),
          } as unknown as SecretManagerClient;
          const expected = expectedAdminKey(stored);

          const outcome = await fetchAdminKey(secrets, "p0_admin").then(
            (key) => ({ key }),
            (error: unknown) => ({ error })
          );

          if ("key" in outcome) {
            expect(outcome.key).toEqual(expected);
            expect(Object.keys(outcome.key).sort()).toEqual([
              "client_id",
              "client_secret",
            ]);
            return "accepted";
          }
          expect(expected).toBeUndefined();
          expect(outcome.error).toBeInstanceOf(ConnectorError);
          expect((outcome.error as ConnectorError).data.type).toBe(
            "validation_error"
          );
          expect(rendered(outcome.error)).not.toContain(CANARY);
          return "refused";
        }
      );

      expect(counts.accepted).toBeGreaterThan(RUNS / 10);
      expect(counts.refused).toBeGreaterThan(RUNS / 10);
    },
    TIMEOUT
  );
});

// The rule, written another way.
const isStorable = (field: string) =>
  field.length > 0 &&
  [...field].every((character) => ALPHANUMERIC.includes(character));

describe("setGrantSecret, on generated keys", () => {
  it(
    "stores exactly the keys of letters and digits, so that the secret splits back at the colon, and quotes none of a refused key",
    async () => {
      const counts = await forAll(
        SEED,
        RUNS,
        (random) => ({
          client_id: keyField(random),
          client_secret: keyField(random),
        }),
        async (key) => {
          const written: string[] = [];
          const secrets = {
            createSecret: vi.fn(async () => ({})),
            createSecretVersion: vi.fn(async ({ value }: { value: Buffer }) => {
              written.push(value.toString("utf8"));
              return VERSION;
            }),
          } as unknown as SecretManagerClient;
          const storable =
            isStorable(key.client_id) && isStorable(key.client_secret);

          const error = await setGrantSecret(secrets, "p0_grant", key).then(
            () => undefined,
            (e: unknown) => e
          );

          if (error === undefined) {
            expect(storable).toBe(true);
            expect(written).toHaveLength(1);
            expect(written[0]?.split(":")).toEqual([
              key.client_id,
              key.client_secret,
            ]);
            return "stored";
          }
          expect(storable).toBe(false);
          expect(error).toBeInstanceOf(ConnectorError);
          expect(rendered(error)).not.toContain(CANARY);
          expect(secrets.createSecret).not.toHaveBeenCalled();
          expect(written).toEqual([]);
          return "refused";
        }
      );

      expect(counts.stored).toBeGreaterThan(RUNS / 10);
      expect(counts.refused).toBeGreaterThan(RUNS / 10);
    },
    TIMEOUT
  );
});
