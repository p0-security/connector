import { ConnectorError } from "@p0security/connector-core";

// ClickHouse's own limit on a name is the file system's, 255 bytes.
const MAX_IDENTIFIER_BYTES = 255;

/**
 * A database or table name as a ClickHouse identifier, in backticks.
 *
 * A backslash and a backtick are each escaped with a backslash, so no name
 * can close the quote: with only backticks escaped, a name ending in `\`
 * would. An empty name, one with a NUL or a line break, and one longer than
 * ClickHouse allows are refused.
 */
export const quoteIdentifier = (name: string): string => {
  if (name === "" || /[\0\n\r]/.test(name)) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "A ClickHouse name can't be empty, or hold a NUL or a line break.",
      payload: {},
    });
  }
  if (Buffer.byteLength(name, "utf8") > MAX_IDENTIFIER_BYTES) {
    throw new ConnectorError({
      type: "validation_error",
      message: `A ClickHouse name can be at most ${MAX_IDENTIFIER_BYTES} bytes.`,
      payload: {},
    });
  }
  return `\`${name.replace(/[\\`]/g, (c) => `\\${c}`)}\``;
};

/** `database.table`, each part quoted with {@link quoteIdentifier}. */
export const quoteTable = ({
  database,
  table,
}: {
  database: string;
  table: string;
}): string => `${quoteIdentifier(database)}.${quoteIdentifier(table)}`;
