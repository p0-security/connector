import type { LambdaClient } from "@aws-sdk/client-lambda";
import { InvokeCommand, LogType } from "@aws-sdk/client-lambda";

import type { CloudFunctionClient } from "./link.ts";

/**
 * Creates a new AWS Lambda cloud function client.
 *
 * @summary Creates a new AWS Lambda cloud function client.
 * @category Low-Level
 *
 * @param params.funcName The name of the AWS Lambda function - either the function name or full ARN.
 * @param params.client The AWS Lambda client to use for invocation.
 * @returns A client that invokes the AWS Lambda function.
 *
 * @see {@link https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/Package/-aws-sdk-credential-providers/ @aws-sdk/credential-providers}
 * for details on AWS credential providers.
 */
export const newAwsLambdaCloudFunctionTestClient = (params: {
  funcName: string;
  client: LambdaClient;
}): CloudFunctionClient => {
  const { funcName, client } = params;

  return async (input, abortSignal) => {
    const command = new InvokeCommand({
      FunctionName: funcName,
      Payload: input,
      LogType: LogType.Tail,
    });
    const { Payload, LogResult } = await client.send(command, {
      abortSignal,
    });
    if (!Payload || !LogResult) {
      throw new Error("Invalid response from AWS Lambda");
    }
    // Uint8Array#buffer widened to ArrayBufferLike in newer @types/node; the
    // AWS SDK always backs this with a plain ArrayBuffer at runtime.
    return Payload.buffer as ArrayBuffer;
  };
};
