export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * Base fetch wrapper for all API calls.
 * Automatically handles JSON parsing, error throwing, and relative URL mapping.
 */
export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const url = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;

  // When SSR in TanStack Start, you might need a full URL if relative fails,
  // but let's stick to standard relative URL for now since it relies on Vite proxy.
  const response = await fetch(url, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    // Attempt to parse JSON error message from the server
    const errorData = await response.json().catch(() => ({}));
    throw new ApiError(
      response.status,
      errorData.error || response.statusText || "An API error occurred",
    );
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}
