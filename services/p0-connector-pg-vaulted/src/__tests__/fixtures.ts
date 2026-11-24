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
