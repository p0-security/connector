import { newCustomAppCloudRunServer } from "@p0security/connector-sdk";

import { newActions } from "./actions.ts";

const run = newCustomAppCloudRunServer({ actions: newActions });

// Binds an Express server on $PORT (Cloud Run sets this; the SDK defaults to
// 8080) serving the connector's tRPC router under /trpc.
run();
