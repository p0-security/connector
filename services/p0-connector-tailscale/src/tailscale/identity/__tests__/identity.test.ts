import type * as Sts from "@aws-sdk/client-sts";
import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { thrown } from "../../../__tests__/helpers.ts";
import { AWS_TOKEN_LIFETIME_SECONDS, awsIdentityToken } from "../aws.ts";
import { gcpIdentityToken } from "../gcp.ts";
import { federatedAudience } from "../source.ts";

const sts = vi.hoisted(() => ({ send: vi.fn() }));

// The real STS module with only the client and command replaced, so error
// classes such as `STSServiceException` stay the real ones.
vi.mock("@aws-sdk/client-sts", async (importOriginal) => ({
  ...(await importOriginal<typeof Sts>()),
  STSClient: class {
    send = sts.send;
  },
  GetWebIdentityTokenCommand: class {
    constructor(readonly input: unknown) {}
  },
}));

const { STSServiceException } = await vi.importActual<typeof Sts>(
  "@aws-sdk/client-sts"
);

const AUDIENCE = federatedAudience("kAbc1CNTRL");

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("federatedAudience", () => {
  it("is Tailscale's default for the client", () => {
    expect(AUDIENCE).toBe("api.tailscale.com/kAbc1CNTRL");
  });
});

describe("awsIdentityToken", () => {
  it("asks STS for a 300-second token for the audience, with a timeout", async () => {
    sts.send.mockResolvedValue({ WebIdentityToken: "aws.jwt.sig" });

    await expect(awsIdentityToken(AUDIENCE)).resolves.toBe("aws.jwt.sig");

    const [command, options] = sts.send.mock.calls[0] ?? [];
    expect(command.input).toEqual({
      Audience: [AUDIENCE],
      SigningAlgorithm: "ES384",
      DurationSeconds: 300,
    });
    expect(AWS_TOKEN_LIFETIME_SECONDS).toBe(300);
    expect(options.abortSignal).toBeInstanceOf(AbortSignal);
  });

  it.each([
    [
      "OutboundWebIdentityFederationDisabledException",
      "insufficient_privileges",
    ],
    ["AccessDenied", "insufficient_privileges"],
    ["Throttling", "upstream_unavailable"],
  ])("maps STS's %s to %s", async (name, type) => {
    sts.send.mockRejectedValue(
      new STSServiceException({ name, $fault: "client", $metadata: {} })
    );

    const error = await thrown(() => awsIdentityToken(AUDIENCE));

    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe(type);
  });

  it("refuses an empty answer", async () => {
    sts.send.mockResolvedValue({});
    const error = await thrown(() => awsIdentityToken(AUDIENCE));
    expect((error as ConnectorError).data.type).toBe("unknown");
  });
});

describe("gcpIdentityToken", () => {
  it("asks the metadata server for a full-format token for the audience", async () => {
    const fetch = vi.fn(async () => new Response("aaa.bbb.ccc\n"));
    vi.stubGlobal("fetch", fetch);

    await expect(gcpIdentityToken(AUDIENCE)).resolves.toBe("aaa.bbb.ccc");

    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    const parsed = new URL(url);
    expect(`${parsed.origin}${parsed.pathname}`).toBe(
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
    );
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      audience: AUDIENCE,
      format: "full",
    });
    expect(init.headers).toEqual({ "Metadata-Flavor": "Google" });
  });

  it("maps a refusal to insufficient_privileges", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("no", { status: 403 }))
    );
    const error = await thrown(() => gcpIdentityToken(AUDIENCE));
    expect((error as ConnectorError).data.type).toBe("insufficient_privileges");
  });

  it("maps no answer to upstream_unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed");
      })
    );
    const error = await thrown(() => gcpIdentityToken(AUDIENCE));
    expect((error as ConnectorError).data.type).toBe("upstream_unavailable");
  });
});
