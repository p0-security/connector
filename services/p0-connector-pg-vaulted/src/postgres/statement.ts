import { ConnectorError } from "@p0security/connector-core";
import { z } from "zod";

import { isIdentifier } from "../identifier.ts";
import type { PgQuery } from "./client.ts";

/**
 * A statement that takes no bindings, such as `CREATE ROLE`, `ALTER ROLE`,
 * `COMMENT`, `GRANT` and `REVOKE`: a template for PostgreSQL's `format()`
 * and its arguments, in order. `%I` stands for a name and `%L` for a
 * literal. A template is a constant in the code, never built from a value.
 */
export type Statement = { template: string; args: readonly string[] };

const built = z.tuple([z.object({ statement: z.string().min(1) })]);

/**
 * Runs `statement`. PostgreSQL builds its text from the template and the
 * arguments, which reach it as bindings, so it does all the quoting and the
 * connector puts no value into SQL. A name must still be one
 * {@link isIdentifier} accepts.
 *
 * The built text can hold a password's verifier, so it is never logged, and
 * no error holds it.
 */
export const execute = async (
  query: PgQuery,
  { template, args }: Statement
) => {
  const isName = (template.match(/%[IL]/g) ?? []).map((spec) => spec === "%I");
  if (args.some((arg, index) => isName[index] && !isIdentifier(arg))) {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid PostgreSQL role name",
      payload: {},
    });
  }
  const bindings = [template, ...args];
  // An untyped parameter leaves `format()` unable to tell its type.
  const parameters = bindings.map((_, index) => `$${index + 1}::text`);
  const rows = await query(
    `SELECT format(${parameters.join(", ")}) AS statement`,
    bindings
  );
  const parsed = built.safeParse(rows);
  if (!parsed.success) {
    throw new ConnectorError({
      type: "unknown",
      message:
        "PostgreSQL did not build the statement the connector asked for.",
      payload: {},
    });
  }
  await query(parsed.data[0].statement);
};
