export const target = {
  host: "orders.cluster-abc123.us-east-1.rds.amazonaws.com",
  port: 5432,
  database: "postgres",
  managerSecret:
    "p0/install/postgres/vpc-0a1b2c3d4e5f67890/orders-prod/p0manager",
};

/** P0's id of the fixture target: the `<target id>` of its manager secret. */
export const TARGET_ID = "orders-prod";
