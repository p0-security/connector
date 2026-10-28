import type * as Sts from "@aws-sdk/client-sts";
import { vi } from "vitest";

/**
 * The fake STS client's `send`. Every suite that federates mocks
 * `@aws-sdk/client-sts` with {@link fakeStsModule}:
 *
 * ```ts
 * vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
 *   (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
 * );
 * ```
 *
 * and {@link resetBetweenTests} in `http.ts` gives it a token before each test.
 * This file imports nothing that loads the STS module itself, because the
 * mock factory above imports it while that module is being mocked.
 */
export const stsSend = vi.fn();

/** The AWS web identity token the fake STS client returns by default. */
export const AWS_JWT = "aws.web-identity.jwt";

/**
 * The real STS module with only the client and command replaced, so error
 * classes such as `STSServiceException` stay the real ones.
 */
export const fakeStsModule = async (
  importOriginal: () => Promise<typeof Sts>
): Promise<Record<string, unknown>> => ({
  ...(await importOriginal()),
  STSClient: class {
    send = stsSend;
  },
  GetWebIdentityTokenCommand: class {
    constructor(readonly input: unknown) {}
  },
});
