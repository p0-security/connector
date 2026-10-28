import { describe, expect, it } from "vitest";

import { iamPolicyToDatasetAcl } from "../resource.ts";

describe("iamPolicyToDatasetAcl", () => {
  it("preserves the full member string for WIF principal members", () => {
    const member =
      "principal://iam.googleapis.com/projects/279175114813/locations/global/workloadIdentityPools/p0-wif-pool-gcp-wif/subject/https://p0-agent-lab.p0-lab1.dev/mcps/gcp-bq/bff6a64d-6a9e-40c3-b4b9-30ba7b2e2ced";

    const acl = iamPolicyToDatasetAcl({
      bindings: [{ role: "roles/bigquery.dataViewer", members: [member] }],
    });

    expect(acl).toEqual([
      { iamMember: member, role: "roles/bigquery.dataViewer" },
    ]);
  });

  it("preserves the full member string for serviceAccount members", () => {
    const member = "serviceAccount:foo@bar.iam.gserviceaccount.com";

    const acl = iamPolicyToDatasetAcl({
      bindings: [{ role: "roles/bigquery.dataEditor", members: [member] }],
    });

    expect(acl).toEqual([
      { iamMember: member, role: "roles/bigquery.dataEditor" },
    ]);
  });
});
