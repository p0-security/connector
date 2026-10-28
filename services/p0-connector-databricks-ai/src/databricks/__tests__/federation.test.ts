import type * as Sts from "@aws-sdk/client-sts";
import { ConnectorError } from "@p0security/connector";
import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  accountContext,
  fetchCalls,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { AWS_JWT, stsSend } from "../../__tests__/sts.ts";
import {
  AWS_TOKEN_LIFETIME_SECONDS,
  DATABRICKS_TOKEN_AUDIENCE,
  databricksAccessToken,
} from "../federation.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const { STSServiceException, OutboundWebIdentityFederationDisabledException } =
  await vi.importActual<typeof Sts>("@aws-sdk/client-sts");

/** An STS error the way the SDK raises it for a response that isn't modeled as its own class. */
const stsError = (name: string, fault: "client" | "server") =>
  new STSServiceException({ name, $fault: fault, $metadata: {} });

const errorFor = async () => {
  const error = await databricksAccessToken(accountContext()).catch(
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("databricksAccessToken", () => {
  describe("token exchange", () => {
    it("mints a 15-minute AWS outbound identity token for the databricks audience, with a timeout", async () => {
      stubFetch();
      await databricksAccessToken(accountContext());

      expect(stsSend).toHaveBeenCalledTimes(1);
      const [command, options] = stsSend.mock.calls[0] ?? [];
      expect(command.input).toEqual({
        Audience: [DATABRICKS_TOKEN_AUDIENCE],
        SigningAlgorithm: "RS256",
        DurationSeconds: 900,
      });
      expect(options.abortSignal).toBeInstanceOf(AbortSignal);
    });

    it("exchanges it at the account token endpoint (RFC 8693) and returns the Databricks token", async () => {
      const fetchMock = stubFetch();

      await expect(databricksAccessToken(accountContext())).resolves.toBe(
        "dbx-token-1"
      );

      const [exchange] = fetchCalls(fetchMock);
      expect(exchange?.url).toBe(
        `${ACCOUNTS_URL}/oidc/accounts/${ACCOUNT_ID}/v1/token`
      );
      expect(exchange?.init.method).toBe("POST");
      expect(exchange?.init.headers["Content-Type"]).toBe(
        "application/x-www-form-urlencoded"
      );
      expect(
        Object.fromEntries(new URLSearchParams(exchange?.init.body))
      ).toEqual({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: AWS_JWT,
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        client_id: APPLICATION_ID,
        scope: "all-apis",
      });
    });

    it("sends the connector's User-Agent on the exchange", async () => {
      const fetchMock = stubFetch();
      await databricksAccessToken(accountContext({ requestId: "req-777" }));

      expect(fetchCalls(fetchMock)[0]?.init.headers["User-Agent"]).toBe(
        "p0-connector-databricks-ai/1.0.0 request/req-777"
      );
    });

    describe("STS failures", () => {
      it("reports outbound identity federation being disabled as an install problem", async () => {
        stubFetch();
        stsSend.mockRejectedValue(
          new OutboundWebIdentityFederationDisabledException({
            message: "disabled",
            $metadata: {},
          })
        );

        const data = await errorFor();
        expect(data).toMatchObject({
          type: "insufficient_privileges",
          payload: { error: "OutboundWebIdentityFederationDisabledException" },
        });
        expect(data.message).toContain("outbound identity federation");
      });

      it("reports a role that may not mint tokens as an install problem", async () => {
        stubFetch();
        stsSend.mockRejectedValue(stsError("AccessDenied", "client"));

        await expect(errorFor()).resolves.toMatchObject({
          type: "insufficient_privileges",
          payload: { error: "AccessDenied" },
        });
      });

      it("reports a throttle that outlived the SDK's retries as STS being unavailable, not an install problem", async () => {
        stubFetch();
        stsSend.mockRejectedValue(stsError("Throttling", "client"));

        await expect(errorFor()).resolves.toMatchObject({
          type: "upstream_unavailable",
          payload: { error: "Throttling" },
        });
      });

      it("reports an STS server fault as STS being unavailable", async () => {
        stubFetch();
        stsSend.mockRejectedValue(stsError("InternalFailure", "server"));

        await expect(errorFor()).resolves.toMatchObject({
          type: "upstream_unavailable",
        });
      });

      it("reports a network error or timeout as STS being unavailable", async () => {
        stubFetch();
        stsSend.mockRejectedValue(
          Object.assign(new Error("aborted"), { name: "TimeoutError" })
        );

        await expect(errorFor()).resolves.toMatchObject({
          type: "upstream_unavailable",
          payload: { error: "TimeoutError" },
        });
      });

      it("reports a success without a token as unknown", async () => {
        const fetchMock = stubFetch();
        stsSend.mockResolvedValue({});

        await expect(errorFor()).resolves.toMatchObject({ type: "unknown" });
        expect(fetchMock).not.toHaveBeenCalled();
      });
    });

    it.each([400, 401])(
      "reports a rejected exchange (%i) as an install problem naming the audience, without leaking the AWS token",
      async (status) => {
        vi.stubGlobal(
          "fetch",
          vi.fn(async () =>
            jsonResponse(
              {
                error: "invalid_request",
                error_description: "no matching federation policy",
              },
              { status }
            )
          )
        );

        const data = await errorFor();
        expect(data).toMatchObject({
          type: "insufficient_privileges",
          payload: { status, errorCode: "invalid_request" },
        });
        expect(data.message).toContain("no matching federation policy");
        expect(data.message).toContain(
          `federation policy of service principal ${APPLICATION_ID}`
        );
        expect(data.message).toContain('expects the audience "databricks"');
        expect(JSON.stringify(data)).not.toContain(AWS_JWT);
      }
    );

    it("reports the token endpoint being down as Databricks being unavailable", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          jsonResponse({}, { status: 503, statusText: "Service Unavailable" })
        )
      );

      await expect(errorFor()).resolves.toMatchObject({
        type: "upstream_unavailable",
        payload: { status: 503 },
      });
    });

    it("refuses an accounts URL that isn't a Databricks account console before sending the AWS token", async () => {
      const fetchMock = stubFetch();

      await expect(
        databricksAccessToken(
          accountContext({ accountsUrl: "https://accounts.evil.example" })
        )
      ).rejects.toMatchObject({ data: { type: "validation_error" } });
      expect(fetchMock).not.toHaveBeenCalled();
      expect(stsSend).not.toHaveBeenCalled();
    });
  });

  describe("token cache", () => {
    it("reuses a token until it nears expiry", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      // The Databricks token lives as long as the AWS token it came from.
      expect(AWS_TOKEN_LIFETIME_SECONDS).toBe(15 * 60);
      const fetchMock = stubFetch();
      const context = accountContext();

      await expect(databricksAccessToken(context)).resolves.toBe("dbx-token-1");
      vi.advanceTimersByTime(10 * 60 * 1000);
      await expect(databricksAccessToken(context)).resolves.toBe("dbx-token-1");
      expect(fetchCalls(fetchMock).filter(isTokenExchange)).toHaveLength(1);
      expect(stsSend).toHaveBeenCalledTimes(1);

      // Within the token's last minute it is refreshed.
      vi.advanceTimersByTime(4.5 * 60 * 1000);
      await expect(databricksAccessToken(context)).resolves.toBe("dbx-token-2");
      expect(fetchCalls(fetchMock).filter(isTokenExchange)).toHaveLength(2);
      expect(stsSend).toHaveBeenCalledTimes(2);
    });

    it("keeps a separate token per account and service principal", async () => {
      const fetchMock = stubFetch();
      const otherAccount = "11111111-2222-4333-8444-555555555555";

      await expect(databricksAccessToken(accountContext())).resolves.toBe(
        "dbx-token-1"
      );
      await expect(
        databricksAccessToken(accountContext({ accountId: otherAccount }))
      ).resolves.toBe("dbx-token-2");
      await expect(
        databricksAccessToken(accountContext({ applicationId: otherAccount }))
      ).resolves.toBe("dbx-token-3");
      await expect(databricksAccessToken(accountContext())).resolves.toBe(
        "dbx-token-1"
      );

      expect(
        fetchCalls(fetchMock)
          .filter(isTokenExchange)
          .map(({ url }) => url)
      ).toEqual([
        `${ACCOUNTS_URL}/oidc/accounts/${ACCOUNT_ID}/v1/token`,
        `${ACCOUNTS_URL}/oidc/accounts/${otherAccount}/v1/token`,
        `${ACCOUNTS_URL}/oidc/accounts/${ACCOUNT_ID}/v1/token`,
      ]);
    });

    it("shares one exchange between concurrent callers", async () => {
      const fetchMock = stubFetch();
      const context = accountContext();

      const tokens = await Promise.all([
        databricksAccessToken(context),
        databricksAccessToken(context),
        databricksAccessToken(context),
      ]);

      expect(tokens).toEqual(["dbx-token-1", "dbx-token-1", "dbx-token-1"]);
      expect(fetchCalls(fetchMock).filter(isTokenExchange)).toHaveLength(1);
    });

    it("doesn't cache a failed exchange", async () => {
      stsSend.mockRejectedValueOnce(stsError("Throttling", "client"));
      stubFetch();
      const context = accountContext();

      await expect(databricksAccessToken(context)).rejects.toBeInstanceOf(
        ConnectorError
      );
      await expect(databricksAccessToken(context)).resolves.toBe("dbx-token-1");
    });
  });
});
