export const assertNever = (msg: never): never => {
  throw new Error(`Unreachable: ${String(msg)}`);
};
