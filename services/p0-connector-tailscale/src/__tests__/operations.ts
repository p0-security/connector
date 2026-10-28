import type { TailnetCredentials } from "../credentials.ts";
import { CREDENTIALS, EMAIL, FEDERATED_CREDENTIAL } from "./fixtures.ts";

/** A call P0 makes to the connector, for the tests that drive every one. */
export type Operation = {
  path: string;
  /** The tRPC client's method for it. */
  type: "mutate" | "query";
  input: unknown;
  /** Whether the call reads an OAuth client's secret. */
  vault: boolean;
};

const operation =
  (type: Operation["type"]) =>
  (
    path: string,
    credentials: TailnetCredentials,
    input: unknown
  ): Operation => ({
    path: `tailscale.${path}`,
    type,
    input,
    vault: credentials.credential.kind === "vault",
  });

const query = operation("query");
const mutation = operation("mutate");

const REQUEST = "AbCdEf0123456789wxyz";
const POSTURE_CONTEXT = {
  ...CREDENTIALS,
  requestId: REQUEST,
  operation: "grant",
  email: EMAIL,
};

const FEDERATED = { ...CREDENTIALS, credential: FEDERATED_CREDENTIAL };

/** Every call P0 makes, with a working input. */
export const OPERATIONS: [string, Operation][] = [
  [
    "install validation",
    query("install.validation.get", CREDENTIALS, CREDENTIALS),
  ],
  [
    "install validation, federated",
    query("install.validation.get", FEDERATED, FEDERATED),
  ],
  [
    "set a device's posture attributes",
    mutation("accesses.posture.setPoliciesForUser", CREDENTIALS, {
      userId: "nLaptop1CNTRL",
      userBody: { email: EMAIL, deviceId: "nLaptop1CNTRL" },
      policies: [
        { posture: "posture:p0_db", expiresAt: "2026-10-17T20:00:00.000Z" },
      ],
      context: POSTURE_CONTEXT,
    }),
  ],
  [
    "remove a device's posture attributes",
    mutation("accesses.posture.setPoliciesForUser", CREDENTIALS, {
      userId: "nLaptop1CNTRL",
      userBody: { email: EMAIL, deviceId: "nLaptop1CNTRL" },
      policies: [],
      context: { ...POSTURE_CONTEXT, operation: "revoke" },
    }),
  ],
  [
    "find the requestor's device",
    mutation("accesses.posture.identifyUser", CREDENTIALS, {
      userBody: { email: EMAIL, deviceId: "nLaptop1CNTRL" },
      context: POSTURE_CONTEXT,
    }),
  ],
  [
    "list a tailnet's postures",
    query("accesses.posture.list", CREDENTIALS, {
      query: { type: "postures", context: CREDENTIALS },
    }),
  ],
  [
    "list the requestor's devices",
    query("accesses.posture.list", CREDENTIALS, {
      query: { type: "own-devices", context: CREDENTIALS, email: EMAIL },
    }),
  ],
  [
    "check a posture",
    query("install.destination.check", CREDENTIALS, {
      context: CREDENTIALS,
      destination: { type: "posture", target: "posture:p0_db" },
    }),
  ],
];
