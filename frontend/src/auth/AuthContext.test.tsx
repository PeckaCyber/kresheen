import { render, screen } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { expect, it, vi } from "vitest";
import { apiFetch } from "../api/client";
import { AuthProvider, useAuth } from "./AuthContext";

// A request sent as soon as the session is known (here from a child layout effect, which runs before the
// provider's effects) must still sign the user out on a 401.
it("signs the user out on a 401 for a request sent as soon as the session is known", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const body = url.endsWith("/api/auth/me")
        ? { csrf_token: "t", expires_at: "x", role: "owner", email: "a@x.test" }
        : { detail: "expired" };
      return new Response(JSON.stringify(body), {
        status: url.endsWith("/api/auth/me") ? 200 : 401,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  function Early() {
    const { isAuthenticated, signedOutByTimeout } = useAuth();
    useLayoutEffect(() => {
      if (isAuthenticated) void apiFetch("/api/applications").catch(() => undefined);
    }, [isAuthenticated]);
    return <span>{signedOutByTimeout ? "timed-out" : isAuthenticated ? "in" : "out"}</span>;
  }
  render(
    <AuthProvider>
      <Early />
    </AuthProvider>,
  );
  expect(await screen.findByText("timed-out", {}, { timeout: 2000 })).toBeInTheDocument();
});
