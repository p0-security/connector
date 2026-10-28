import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

/**
 * Every access type's `createUser`. P0 never creates Databricks users, so a
 * requestor without one is refused with the same message in every access
 * type. `privilege` never reaches it: its `getUser` always returns the
 * email, and a Databricks user that doesn't exist fails the grant instead
 * (see {@link unknownDatabricksUser}).
 */
export const userMustAlreadyExist = async (
  context: { requestId: string },
  { email }: { email: string }
): Promise<never> => {
  throw new ConnectorError({
    type: "object_not_found",
    message: `No Databricks user \`${email}\`. Users must already exist.`,
    payload: { requestId: context.requestId, query: email },
  });
};

/**
 * The refusal for a grant to an email that names no Databricks principal.
 * `privilege` grants to the email without looking the user up first, so
 * this is how a requestor without a Databricks user learns it. The payload
 * marks it, so {@link isUnknownDatabricksUser} can tell it apart from any
 * other `object_not_found`.
 */
export const unknownDatabricksUser = ({
  requestId,
  principal,
  cause,
}: {
  requestId: string;
  /** The email the grant named. */
  principal: string;
  /** The Databricks error that reported the principal unknown. */
  cause?: unknown;
}) =>
  new ConnectorError({
    type: "object_not_found",
    message: `No Databricks user \`${principal}\`. P0 grants Unity Catalog privileges only to the Databricks user whose username is this email. Ask a Databricks admin to add that user, then request again.`,
    payload: { requestId, query: principal, unknownPrincipal: true },
    cause,
  });

const unknownPrincipalPayload = z.object({ unknownPrincipal: z.literal(true) });

/** Whether `error` is the refusal {@link unknownDatabricksUser} builds. */
export const isUnknownDatabricksUser = (error: unknown) =>
  error instanceof ConnectorError &&
  unknownPrincipalPayload.safeParse(error.data.payload).success;

/** Every access type's `deleteUser`: P0 never created the user, so it never deletes one. */
export const neverDeleteUser = async () => {};
