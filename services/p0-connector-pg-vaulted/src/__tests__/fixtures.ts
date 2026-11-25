export const target = {
  host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
  port: 5432,
  database: "postgres",
  managerSecret:
    "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
};

export const GRANT_SECRET_PREFIX =
  "p0/secrets/postgres/vpc-0a1b2c3d4e5f67890/test-target";
