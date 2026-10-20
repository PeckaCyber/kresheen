// Thin fetch wrapper: same-origin cookie session (credentials: 'include')
// plus the CSRF header every mutating /api/* route requires. CSRF token
// lives in a module-level singleton rather than threaded through every
// call site -- AuthContext is the only thing that ever sets it (on
// login/me), everything else just calls apiFetch().

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

// Called when a request outside /api/auth/ is answered 401, which means the session ended (idle timeout, absolute
// limit, or revoked). AuthContext registers it; auth routes are excluded because a 401 there is a wrong password.
let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (MUTATING_METHODS.has(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }

  const response = await fetch(path, { ...init, method, headers, credentials: "include" });
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/api/auth/")) unauthorizedHandler?.();
    const detail = await response.json().catch(() => null);
    throw new ApiError(
      response.status,
      (detail && typeof detail === "object" && "detail" in detail && String(detail.detail)) ||
        `Request to ${path} failed (${response.status})`,
    );
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}
