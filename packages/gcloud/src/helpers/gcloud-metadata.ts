import axios from "axios";

export const GCLOUD_COMPUTE_METADATA_URL =
  "http://metadata.google.internal/computeMetadata/v1";

const getGcloudComputeMetadata = async <T>(path: string) => {
  const response = await axios.get(`${GCLOUD_COMPUTE_METADATA_URL}/${path}`, {
    headers: { "Metadata-Flavor": "Google" },
    timeout: 2000,
  });
  return response.data as T;
};

export const gcloudServiceMetadata = async () => {
  const serviceAccountEmail = await getGcloudComputeMetadata<string>(
    "instance/service-accounts/default/email"
  );
  const projectId =
    await getGcloudComputeMetadata<string>("project/project-id");
  return { serviceAccountEmail, projectId };
};
