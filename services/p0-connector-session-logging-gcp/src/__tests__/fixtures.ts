import type { GcpAuditLogQuery } from "@p0security/connector-core";

import type { AuditLogEntry } from "../audit/entries.ts";

/**
 * Cloud Audit Log entries as `entries.list` returns them, modelled on
 * recorded entries with identifiers replaced.
 */
export const PROJECT = "acme-prod-381204";

/** Admin Activity: a VM created under a project-level grant. */
export const adminActivity: AuditLogEntry = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    status: {},
    authenticationInfo: {
      principalEmail: "alice@example.com",
      principalSubject: "user:alice@example.com",
    },
    requestMetadata: {
      callerIp: "203.0.113.10",
      callerSuppliedUserAgent: "google-cloud-sdk gcloud/498.0.0",
    },
    serviceName: "compute.googleapis.com",
    methodName: "v1.compute.instances.insert",
    authorizationInfo: [
      {
        permission: "compute.instances.create",
        granted: true,
        resourceAttributes: {
          service: "compute",
          name: `projects/${PROJECT}/zones/us-central1-a/instances/build-7`,
          type: "compute.instances",
        },
        permissionType: "ADMIN_WRITE",
      },
    ],
    resourceName: `projects/${PROJECT}/zones/us-central1-a/instances/build-7`,
    request: { "@type": "type.googleapis.com/compute.instances.insert" },
    resourceLocation: { currentLocations: ["us-central1-a"] },
  },
  insertId: "-k3x9c2e1a4b",
  resource: {
    type: "gce_instance",
    labels: {
      zone: "us-central1-a",
      project_id: PROJECT,
      instance_id: "4471298374651234567",
    },
  },
  timestamp: "2026-11-01T10:20:11.482915Z",
  severity: "NOTICE",
  logName: `projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity`,
  operation: {
    id: "operation-1730456411000-62a1",
    producer: "compute.googleapis.com",
    first: true,
  },
  receiveTimestamp: "2026-11-01T10:20:12.031884512Z",
};

/** Data Access: an object read under a bucket-scoped grant. */
export const dataAccess: AuditLogEntry = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    status: {},
    authenticationInfo: { principalEmail: "alice@example.com" },
    requestMetadata: {
      callerIp: "203.0.113.10",
      callerSuppliedUserAgent: "apitools gsutil/5.30",
      requestAttributes: {
        time: "2026-11-01T10:31:02.118Z",
        auth: {},
      },
      destinationAttributes: {},
    },
    serviceName: "storage.googleapis.com",
    methodName: "storage.objects.get",
    authorizationInfo: [
      {
        resource: "projects/_/buckets/acme-reports/objects/2026/q3.csv",
        permission: "storage.objects.get",
        granted: true,
        resourceAttributes: {},
      },
    ],
    resourceName: "projects/_/buckets/acme-reports/objects/2026/q3.csv",
    resourceLocation: { currentLocations: ["us"] },
  },
  insertId: "1n4fx2je8wq3",
  resource: {
    type: "gcs_bucket",
    labels: {
      bucket_name: "acme-reports",
      project_id: PROJECT,
      location: "us",
    },
  },
  timestamp: "2026-11-01T10:31:02.109884Z",
  severity: "INFO",
  logName: `projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access`,
  receiveTimestamp: "2026-11-01T10:31:02.712451221Z",
};

/** Data Access refused on another bucket. */
export const denied: AuditLogEntry = {
  ...dataAccess,
  protoPayload: {
    ...dataAccess.protoPayload,
    status: {
      code: 7,
      message: "PERMISSION_DENIED",
    },
    methodName: "storage.objects.get",
    authorizationInfo: [
      {
        resource: "projects/_/buckets/acme-payroll/objects/salaries.csv",
        permission: "storage.objects.get",
        granted: false,
        resourceAttributes: {},
      },
    ],
    resourceName: "projects/_/buckets/acme-payroll/objects/salaries.csv",
  },
  insertId: "1n4fx2je8wq4",
  timestamp: "2026-11-01T10:32:00.000000Z",
  severity: "ERROR",
};

/** Alice impersonating a service account to list buckets. */
export const impersonated: AuditLogEntry = {
  ...dataAccess,
  protoPayload: {
    ...dataAccess.protoPayload,
    authenticationInfo: {
      principalEmail: "deployer@acme-prod-381204.iam.gserviceaccount.com",
      serviceAccountDelegationInfo: [
        {
          firstPartyPrincipal: { principalEmail: "Alice@Example.com" },
        },
      ],
    },
    methodName: "storage.buckets.list",
    authorizationInfo: [
      {
        resource: `projects/_/buckets`,
        permission: "storage.buckets.list",
        granted: true,
        resourceAttributes: {},
      },
    ],
    resourceName: `projects/${PROJECT}`,
  },
  insertId: "8b2cq1d9e0a7",
  timestamp: "2026-11-01T11:05:45.000000Z",
};

/** Someone else, who must never come back. */
export const otherPrincipal: AuditLogEntry = {
  ...dataAccess,
  protoPayload: {
    ...dataAccess.protoPayload,
    authenticationInfo: { principalEmail: "mallory@example.com" },
  },
  insertId: "zz-other",
};

export const window = {
  start: "2026-11-01T10:00:00Z",
  end: "2026-11-01T12:00:00Z",
};

export const projectQuery: GcpAuditLogQuery = {
  source: "gcp-audit",
  window,
  projectId: PROJECT,
  principalEmail: "alice@example.com",
  permissions: [
    "compute.instances.create",
    "storage.objects.get",
    "storage.buckets.list",
  ],
  resourcePrefixes: [
    `//cloudresourcemanager.googleapis.com/projects/${PROJECT}`,
  ],
};

export const bucketQuery: GcpAuditLogQuery = {
  ...projectQuery,
  permissions: ["storage.objects.get", "storage.objects.list"],
  resourcePrefixes: [
    "//storage.googleapis.com/projects/_/buckets/acme-reports",
  ],
};
