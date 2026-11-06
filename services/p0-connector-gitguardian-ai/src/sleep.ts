/** Waits `ms` milliseconds. Its own module, so tests can replace it. */
export const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
