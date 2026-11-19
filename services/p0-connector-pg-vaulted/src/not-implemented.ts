/**
 * What every stubbed operation throws. A plain `Error`, because no
 * `ConnectorError` type describes an operation the connector does not have
 * yet.
 */
export const newNotImplementedError = (operation: string) =>
  new Error(`pg-vaulted ${operation} is not implemented`);
