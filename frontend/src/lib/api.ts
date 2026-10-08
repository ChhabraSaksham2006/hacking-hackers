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
  let finalUrl = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;

  if (import.meta.env.DEV) {
    finalUrl = `http://localhost:5000${finalUrl}`;
  }

  // When SSR in TanStack Start, you might need a full URL if relative fails,
  // but let's stick to standard relative URL for now since it relies on Vite proxy.
  const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
  const headers: Record<string, string> = {};
  if (!isFormData) {
    headers["Content-Type"] = "application/json";
  }
  if (options.headers) {
    Object.assign(headers, options.headers);
  }

  const response = await fetch(finalUrl, {
    ...options,
    credentials: "include",
    headers,
  });

  if (!response.ok) {
    // Attempt to parse JSON error message from the server
    const errorData = await response.json().catch(() => ({}));
    
    // Prefer user-friendly human message:
    // 1. errorData.message (if not "AppError")
    // 2. errorData.error (if not "AppError")
    // 3. Fallback based on HTTP status code
    let message =
      (errorData.message && errorData.message !== "AppError" ? errorData.message : null) ||
      (errorData.error && errorData.error !== "AppError" ? errorData.error : null) ||
      errorData.message ||
      errorData.error;

    if (!message || message === "AppError") {
      switch (response.status) {
        case 400:
          message = "Bad request. Please verify your input.";
          break;
        case 401:
          message = "Invalid email or password. Please try again.";
          break;
        case 403:
          message = "Access denied or account verification required.";
          break;
        case 404:
          message = "The requested resource was not found.";
          break;
        case 409:
          message = "An account or resource with those details already exists.";
          break;
        case 429:
          message = "Too many requests. Please slow down and try again later.";
          break;
        case 500:
        default:
          message = response.statusText || "An unexpected error occurred. Please try again.";
      }
    }

    throw new ApiError(response.status, message);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}
