import type { drive_v3 } from "@googleapis/drive";
import { auth, drive } from "@googleapis/drive";

/** The one OAuth scope this connector holds.
 *
 * `drive` rather than `drive.file`: the connector writes permissions on items
 * it did not create, which `drive.file` (created-or-opened-by-this-app only)
 * cannot reach.
 */
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive";

/**
 * Builds the Drive v3 client every call in this connector goes through.
 *
 * Application Default Credentials, and nothing else. On Cloud Run the ambient
 * identity *is* the admin service account that a human has already made an
 * `organizer` on each registered shared drive, so there is no impersonation
 * anywhere in this connector and it holds no second credential.
 */
export const newDriveClient = (): drive_v3.Drive =>
  drive({
    version: "v3",
    auth: new auth.GoogleAuth({ scopes: [DRIVE_SCOPE] }),
  });
