export { gcloudServiceMetadata } from "./helpers/gcloud-metadata.ts";
export {
  createClients,
  getGoogleAuth,
  getServiceAccountEmail,
  CLOUDSQL_LOGIN_SCOPE,
} from "./client.ts";
export { PolicyManager } from "./policy-manager.ts";
export { PolicyRouter } from "./policy-router.ts";
export { verifyToken } from "./helpers/verify-token.ts";
export { fetchDbPassword } from "./helpers/cloudsql.ts";
export { newMemberVerifier } from "./member-verify.ts";
export { newAgenticIdentityPrimitives } from "./agentic-identity/index.ts";
export type {
  AgenticIdentityConnection,
  AgenticIdentityPolicy,
  AgenticIdentityRequestContext,
  AgenticIdentityUserBody,
} from "./agentic-identity/index.ts";
export {
  AGENTIC_IDENTITY_ACCOUNT_ID,
  AGENTIC_IDENTITY_SUBJECT,
  agenticIdentityEmail,
  isAgenticIdentityAccountId,
  isAgenticIdentityEmail,
  isAgenticIdentitySubject,
  isProjectId,
  parseWorkloadIdentityPrincipal,
} from "./agentic-identity/index.ts";
export type {
  AddMemberRequest,
  GcloudServiceMetadata,
  GcloudPolicyResource,
  GcloudIapTunnelInstanceResource,
  GcloudInstanceResource,
  GcloudTableResource,
  GcloudGenericResource,
  GcloudProjectResource,
  GcloudOrganizationResource,
  GcloudPolicyResourceWithProject,
  RemoveMemberRequest,
  RemoveMemberResponse,
} from "./types.ts";
export { conditionalIAMSupported } from "./resource.ts";
