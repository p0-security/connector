import { ConnectorError } from "@p0security/connector-core";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type Random,
  anyJson,
  anyString,
  fileSeed,
  forAll,
  mutateJson,
} from "../../__tests__/generate.ts";
import {
  createApiKey,
  createContentAccess,
  createModelSet,
  createPermissionSet,
  createRole,
  createServiceAccount,
  deleteContentAccess,
  deleteServiceAccount,
  findFolder,
  findModelSet,
  findPermissionSet,
  findRole,
  listContentAccess,
  listDirectRoleIds,
  listGroupsWithRoles,
  listModels,
  listPermissionParents,
  listServiceAccountIds,
  login,
  logout,
  setUserName,
  setUserRoles,
  updateContentAccess,
} from "../looker-api.ts";

/**
 * Every client call, on any response Looker might send: the call either
 * returns a value of its stated shape, or throws a ConnectorError. It never
 * throws anything else, and its error never quotes the key or the token.
 */

const SEED = fileSeed();
const RUNS = 400;
const TIMEOUT = 30_000;

const mockedFetch = vi.fn();
vi.stubGlobal("fetch", mockedFetch);

const BASE_URL = "https://example.looker.app";
const CANARY = "CANARY";
const ADMIN_KEY = { client_id: "admin-id", client_secret: `${CANARY}admin` };
const SESSION = { baseUrl: BASE_URL, accessToken: `${CANARY}token` };

const CONNECTOR_ERROR_TYPES = [
  "insufficient_privileges",
  "object_not_found",
  "already_exists",
  "upstream_unavailable",
  "rate_limited",
  "unknown",
];

const KEYS = [
  "id",
  "name",
  "message",
  "errors",
  "field",
  "access_token",
  "client_id",
  "client_secret",
  "service_account_name",
  "code",
  "permission",
  "parent",
  "permissions",
  "models",
  "permission_set",
  "model_set",
  "label",
  "content_metadata_id",
  "user_id",
  "permission_type",
  "include_by_default",
  "roles",
];

type Reply = {
  status: number;
  /** What `response.json()` resolves to, or `undefined` when it throws */
  body: unknown;
};

/** A Looker id, sometimes a number as older Looker versions send. */
const anyId = (random: Random) =>
  random.chance(0.8) ? String(random.int(1, 999)) : random.int(1, 999);

/** A reply to a call: mostly a success that is close to the right shape,
 * sometimes an error, sometimes not JSON. */
const reply = (random: Random, valid: unknown): Reply => {
  const roll = random.next();
  if (roll < 0.65)
    return { status: 200, body: mutateJson(random, valid, KEYS) };
  if (roll < 0.7) return { status: 200, body: undefined };
  if (roll < 0.75) return { status: 204, body: undefined };
  return {
    status: random.pick([400, 401, 403, 404, 409, 422, 429, 500, 502, 503]),
    body: random.chance(0.8)
      ? mutateJson(
          random,
          {
            message: random.pick([
              "Not found",
              "Validation Failed",
              "API quota exceeded",
              anyString(random),
            ]),
            errors: [{ field: "name", message: anyString(random) }],
          },
          KEYS
        )
      : anyJson(random, KEYS),
  };
};

const respond = ({ status, body }: Reply) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: "Status",
  json: async () => {
    if (body === undefined) throw new SyntaxError("Unexpected token <");
    return body;
  },
});

type Call = {
  name: string;
  /** A response of the right shape */
  valid: (random: Random) => unknown;
  run: () => Promise<unknown>;
  /** Checks a returned value's shape */
  check: (result: unknown) => void;
};

const nonEmptyString = (value: unknown) => {
  expect(typeof value).toBe("string");
  expect((value as string).length).toBeGreaterThan(0);
};

const stringList = (value: unknown) => {
  expect(Array.isArray(value)).toBe(true);
  for (const item of value as unknown[]) expect(typeof item).toBe("string");
};

/** A found object has exactly the name that was asked for. */
const named = (object: Record<string, unknown>, name?: string) => {
  nonEmptyString(object.id);
  if (name === undefined) expect(typeof object.name).toBe("string");
  else expect(object.name).toBe(name);
};

const permissionSetShape = (set: unknown, name?: string) => {
  const object = set as Record<string, unknown>;
  expect(Object.keys(object).sort()).toEqual(["id", "name", "permissions"]);
  named(object, name);
  stringList(object.permissions);
};

const modelSetShape = (set: unknown, name?: string) => {
  const object = set as Record<string, unknown>;
  expect(Object.keys(object).sort()).toEqual(["id", "models", "name"]);
  named(object, name);
  stringList(object.models);
};

const roleShape = (role: unknown, name?: string) => {
  const object = role as Record<string, unknown>;
  expect(Object.keys(object).sort()).toEqual([
    "id",
    "modelSetId",
    "name",
    "permissionSetId",
  ]);
  named(object, name);
  for (const id of [object.permissionSetId, object.modelSetId]) {
    if (id !== undefined) nonEmptyString(id);
  }
};

const CALLS: Call[] = [
  {
    name: "login",
    valid: () => ({
      access_token: "t",
      token_type: "Bearer",
      expires_in: 3600,
    }),
    run: () => login(BASE_URL, ADMIN_KEY),
    check: (session) => {
      expect(Object.keys(session as object).sort()).toEqual([
        "accessToken",
        "baseUrl",
      ]);
      const { baseUrl, accessToken } = session as Record<string, unknown>;
      expect(baseUrl).toBe(BASE_URL);
      nonEmptyString(accessToken);
    },
  },
  {
    name: "logout",
    valid: () => undefined,
    run: () => logout(SESSION),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "createServiceAccount",
    valid: (random) => ({ id: anyId(random) }),
    run: () => createServiceAccount(SESSION, "p0_grant"),
    check: nonEmptyString,
  },
  {
    name: "setUserName",
    valid: (random) => ({ id: anyId(random) }),
    run: () => setUserName(SESSION, "42", { firstName: "P0", lastName: "x" }),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "createApiKey",
    valid: (random) => ({
      id: anyId(random),
      client_id: `${CANARY}id`,
      client_secret: `${CANARY}secret`,
    }),
    run: () => createApiKey(SESSION, "42"),
    check: (key) => {
      expect(Object.keys(key as object).sort()).toEqual([
        "client_id",
        "client_secret",
      ]);
      const { client_id, client_secret } = key as Record<string, unknown>;
      nonEmptyString(client_id);
      nonEmptyString(client_secret);
    },
  },
  {
    name: "listServiceAccountIds",
    valid: (random) =>
      Array.from({ length: random.int(0, 4) }, () => ({
        id: anyId(random),
        service_account_name: random.pick([
          "p0_grant",
          "P0_GRANT",
          "other",
          null,
        ]),
      })),
    run: () => listServiceAccountIds(SESSION, "p0_grant"),
    check: (ids) => {
      expect(Array.isArray(ids)).toBe(true);
      for (const id of ids as unknown[]) nonEmptyString(id);
    },
  },
  {
    name: "deleteServiceAccount",
    valid: () => undefined,
    run: () => deleteServiceAccount(SESSION, "42"),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "listPermissionParents",
    valid: (random) =>
      Array.from({ length: random.int(0, 4) }, () => ({
        permission: random.pick(["access_data", "see_looks", "explore", null]),
        parent: random.pick(["access_data", null, undefined]),
      })),
    run: () => listPermissionParents(SESSION),
    check: (parents) => {
      expect(parents).toBeInstanceOf(Map);
      for (const [permission, parent] of parents as Map<unknown, unknown>) {
        nonEmptyString(permission);
        if (parent !== null) nonEmptyString(parent);
      }
    },
  },
  {
    name: "findPermissionSet",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        id: anyId(random),
        name: random.pick(["p0", "P0", "p0x", null]),
        permissions: random.pick([["access_data"], [], null]),
      })),
    run: () => findPermissionSet(SESSION, "p0"),
    check: (set) => {
      if (set !== undefined) permissionSetShape(set, "p0");
    },
  },
  {
    name: "createPermissionSet",
    valid: (random) => ({
      id: anyId(random),
      name: "p0",
      permissions: ["access_data"],
    }),
    run: () =>
      createPermissionSet(SESSION, {
        name: "p0",
        permissions: ["access_data"],
      }),
    check: (set) => permissionSetShape(set),
  },
  {
    name: "findModelSet",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        id: anyId(random),
        name: random.pick(["p0", "P0", "p0x", null]),
        models: random.pick([["thelook"], [], null]),
      })),
    run: () => findModelSet(SESSION, "p0"),
    check: (set) => {
      if (set !== undefined) modelSetShape(set, "p0");
    },
  },
  {
    name: "createModelSet",
    valid: (random) => ({ id: anyId(random), name: "p0", models: ["thelook"] }),
    run: () => createModelSet(SESSION, { name: "p0", models: ["thelook"] }),
    check: (set) => modelSetShape(set),
  },
  {
    name: "findRole",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        id: anyId(random),
        name: random.pick(["p0", "P0", "p0x", null]),
        permission_set: random.pick([{ id: anyId(random) }, null]),
        model_set: random.pick([{ id: anyId(random) }, undefined]),
      })),
    run: () => findRole(SESSION, "p0"),
    check: (role) => {
      if (role !== undefined) roleShape(role, "p0");
    },
  },
  {
    name: "createRole",
    valid: (random) => ({
      id: anyId(random),
      name: "p0",
      permission_set: { id: anyId(random) },
      model_set: { id: anyId(random) },
    }),
    run: () =>
      createRole(SESSION, {
        name: "p0",
        permissionSetId: "1",
        modelSetId: "2",
      }),
    check: (role) => roleShape(role),
  },
  {
    name: "setUserRoles",
    valid: (random) => [{ id: anyId(random) }],
    run: () => setUserRoles(SESSION, "42", ["3"]),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "listDirectRoleIds",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({ id: anyId(random) })),
    run: () => listDirectRoleIds(SESSION, "42"),
    check: (ids) => {
      expect(Array.isArray(ids)).toBe(true);
      for (const id of ids as unknown[]) nonEmptyString(id);
    },
  },
  {
    name: "listModels",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        name: random.pick(["thelook", "finance", null, ""]),
        label: random.pick(["The Look", null, ""]),
      })),
    run: () => listModels(SESSION),
    check: (models) => {
      expect(Array.isArray(models)).toBe(true);
      for (const model of models as Record<string, unknown>[]) {
        expect(Object.keys(model).sort()).toEqual(["label", "name"]);
        nonEmptyString(model.name);
        nonEmptyString(model.label);
      }
    },
  },
  {
    name: "findFolder",
    valid: (random) => ({ id: "77", content_metadata_id: anyId(random) }),
    run: () => findFolder(SESSION, "77"),
    check: (folder) => {
      if (folder === undefined) return;
      expect(Object.keys(folder as object)).toEqual(["contentMetadataId"]);
      nonEmptyString((folder as Record<string, unknown>).contentMetadataId);
    },
  },
  {
    name: "listContentAccess",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        id: anyId(random),
        user_id: random.pick([anyId(random), null, undefined]),
        permission_type: random.pick(["edit", "view", null]),
      })),
    run: () => listContentAccess(SESSION, "770"),
    check: (accesses) => {
      expect(Array.isArray(accesses)).toBe(true);
      for (const access of accesses as Record<string, unknown>[]) {
        nonEmptyString(access.id);
        if (access.userId !== undefined) nonEmptyString(access.userId);
        expect(typeof access.permissionType).toBe("string");
      }
    },
  },
  {
    name: "createContentAccess",
    valid: (random) => ({ id: anyId(random) }),
    run: () =>
      createContentAccess(SESSION, {
        contentMetadataId: "770",
        userId: "42",
        permissionType: "edit",
      }),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "updateContentAccess",
    valid: (random) => ({ id: anyId(random) }),
    run: () => updateContentAccess(SESSION, "9", "edit"),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "deleteContentAccess",
    valid: () => undefined,
    run: () => deleteContentAccess(SESSION, "9"),
    check: (result) => expect(result).toBeUndefined(),
  },
  {
    name: "listGroupsWithRoles",
    valid: (random) =>
      Array.from({ length: random.int(0, 3) }, () => ({
        id: anyId(random),
        name: random.pick(["All Users", "BI", null]),
        include_by_default: random.pick([true, false, null, undefined]),
        roles: random.pick([[{ name: "Viewer" }, { name: null }], [], null]),
      })),
    run: () => listGroupsWithRoles(SESSION),
    check: (groups) => {
      expect(Array.isArray(groups)).toBe(true);
      for (const group of groups as Record<string, unknown>[]) {
        nonEmptyString(group.id);
        expect(typeof group.name).toBe("string");
        expect(typeof group.includeByDefault).toBe("boolean");
        for (const role of group.roles as unknown[]) nonEmptyString(role);
      }
    },
  },
];

beforeEach(() => {
  mockedFetch.mockReset();
});

describe.each(CALLS)("$name, on generated Looker responses", (call) => {
  it(
    "returns its stated shape or throws a ConnectorError that quotes no key or token",
    async () => {
      const counts = await forAll(
        SEED,
        RUNS,
        (random) => reply(random, call.valid(random)),
        async (generated) => {
          mockedFetch.mockReset();
          mockedFetch.mockResolvedValue(respond(generated));

          const outcome = await call.run().then(
            (result) => ({ result }),
            (error: unknown) => ({ error })
          );

          if ("result" in outcome) {
            call.check(outcome.result);
            return "returned";
          }
          const { error } = outcome;
          if (!(error instanceof ConnectorError)) {
            throw new Error(`threw something else: ${inspect(error)}`);
          }
          expect(CONNECTOR_ERROR_TYPES).toContain(error.data.type);
          // A success body can hold a key, so an error about one quotes none
          // of it. Looker's own error message is quoted, so this is checked
          // for successes only.
          if (error.data.type === "already_exists") {
            // The client's own error for a create whose name is taken.
            expect([409, 422]).toContain(generated.status);
          } else if (generated.status >= 300) {
            expect(error.data.payload.status).toBe(generated.status);
          } else {
            expect(
              `${error.data.message}\n${JSON.stringify(error.data.payload)}`
            ).not.toContain(CANARY);
          }
          return "threw";
        }
      );

      expect(counts.returned).toBeGreaterThan(RUNS / 20);
      expect(counts.threw).toBeGreaterThan(RUNS / 20);
    },
    TIMEOUT
  );
});

/**
 * Looker's name search, as its docs describe it: it ignores case, `%` stands
 * for any run of characters and `_` for any one.
 */
const lookerNameSearch = (pattern: string, name: string) =>
  new RegExp(
    `^${[...pattern]
      .map((character) =>
        character === "%"
          ? ".*"
          : character === "_"
            ? "."
            : character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      )
      .join("")}$`,
    "isu"
  ).test(name);

const NAME_CHARACTERS = ["a", "b", "A", "B", "_", "%", "-", "1"];

type Search = {
  wanted: string;
  /** Everything of the kind that the instance holds */
  stored: { id: number | string; name: string }[];
};

/** A name with wildcards in it, and an instance that holds near misses of it:
 * the name in another case, with a wildcard filled in, and others. */
const generateSearch = (random: Random): Search => {
  const wanted = random.string(NAME_CHARACTERS, random.int(1, 6));
  const nearMiss = () => {
    switch (random.int(0, 4)) {
      case 0:
        return wanted;
      case 1:
        return random.chance(0.5) ? wanted.toUpperCase() : wanted.toLowerCase();
      case 2:
        return [...wanted]
          .map((character) =>
            character === "_"
              ? random.pick(NAME_CHARACTERS)
              : character === "%"
                ? random.string(NAME_CHARACTERS, random.int(0, 3))
                : character
          )
          .join("");
      case 3:
        return `${wanted}${random.pick(NAME_CHARACTERS)}`;
      default:
        return random.string(NAME_CHARACTERS, random.int(1, 6));
    }
  };
  const ids = new Set<number>();
  while (ids.size < random.int(0, 6)) ids.add(random.int(1, 300));
  return {
    wanted,
    stored: [...ids].map((id) => ({
      id: random.chance(0.5) ? String(id) : id,
      name: nearMiss(),
    })),
  };
};

describe.each([
  { kind: "findPermissionSet", find: findPermissionSet },
  { kind: "findModelSet", find: findModelSet },
  { kind: "findRole", find: findRole },
])("$kind, on generated names with wildcards", ({ find }) => {
  it(
    "returns the object with exactly the name and the lowest id, whatever else Looker's search matches",
    async () => {
      const counts = await forAll(
        SEED,
        RUNS,
        generateSearch,
        async ({ wanted, stored }) => {
          let matched: Search["stored"] = [];
          mockedFetch.mockReset();
          mockedFetch.mockImplementation(async (url: string) => {
            const pattern = new URL(url).searchParams.get("name") ?? "";
            matched = stored.filter(({ name }) =>
              lookerNameSearch(pattern, name)
            );
            return respond({ status: 200, body: matched });
          });
          const exact = stored
            .filter(({ name }) => name === wanted)
            .map(({ id }) => Number(id));

          const found = await find(SESSION, wanted);

          if (exact.length === 0) {
            expect(found).toBeUndefined();
            return matched.length > 0 ? "refused near misses" : "found nothing";
          }
          expect(found?.name).toBe(wanted);
          expect(found?.id).toBe(String(Math.min(...exact)));
          return matched.length > exact.length
            ? "picked among near misses"
            : "found";
        }
      );

      // The search returned other names, and they were told apart.
      expect(counts["refused near misses"]).toBeGreaterThan(RUNS / 50);
      expect(counts["picked among near misses"]).toBeGreaterThan(RUNS / 50);
      expect(counts["found nothing"]).toBeGreaterThan(0);
    },
    TIMEOUT
  );
});
