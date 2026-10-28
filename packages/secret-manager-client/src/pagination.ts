/** Recursively follows pageTokens via `fetchPage` and returns all items across pages. */
export const listAllPages = async <T>(
  fetchPage: (
    pageToken?: string
  ) => Promise<{ items: T[]; nextPageToken?: string | null }>,
  pageToken?: string
): Promise<T[]> => {
  const page = await fetchPage(pageToken);
  return page.nextPageToken
    ? [...page.items, ...(await listAllPages(fetchPage, page.nextPageToken))]
    : page.items;
};
