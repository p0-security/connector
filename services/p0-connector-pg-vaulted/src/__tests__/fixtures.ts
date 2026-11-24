import type { RequestContext } from "../context.ts";

export const GRANT_KEY = "0123456789abcdef0123456789abcdef";
export const LOGIN = `p0v_${GRANT_KEY}`;

export const target = {
  host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
  port: 5432,
  database: "postgres",
  managerSecret:
    "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
};

export const context: RequestContext = {
  requestId: "r123",
  target,
  targetId: "orders-prod",
  secrets: { manager: "aws", region: "us-east-1" },
  secretName: `p0/secrets/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/${LOGIN}`,
  deadline: "2026-12-01T00:00:00Z",
  comment: "request r123, requestor x@example.com",
  objectOwner: "analyst",
};

/**
 * The passwords and verifiers of the first and the second grant login that a
 * connector with `fakeRandomBytes` prepares: draws 1 and 3 as base64url, and
 * their SCRAM-SHA-256 verifiers with draws 2 and 4 as the salt. The verifiers
 * were computed apart from the connector, with Python's `hashlib`.
 */
export const FIRST_PASSWORD = {
  password: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
  verifier:
    "SCRAM-SHA-256$4096:AgICAgICAgICAgICAgICAg==$gwn/Ia5nKfTgW86qLe4CmPa661/DBKxA7m7WFIMwiIc=:nVytlfOnYH6lobvQt7TdUidTE9wf6skXKWYBbGzn3AM=",
};

export const SECOND_PASSWORD = {
  password: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
  verifier:
    "SCRAM-SHA-256$4096:BAQEBAQEBAQEBAQEBAQEBA==$lyuoa+b5ENjlpm87qVXcgQ4W8HUBT7iXfGvfvrNR6p8=:M7BJ74hnzp8IyZP0q/2LsGJlAJXeRiYmCzYuZHMmycc=",
};
