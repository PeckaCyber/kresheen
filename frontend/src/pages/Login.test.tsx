import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch } from "../api/client";
import { AuthProvider, useAuth } from "../auth/AuthContext";
import { Login } from "./Login";

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderLogin(path = "/login") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("Login providers", () => {
  function stubProviders(providers: unknown[]) {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/auth/me")) return jsonResponse({ detail: "Not authenticated" }, 401);
        if (url.endsWith("/api/capabilities"))
          return jsonResponse({ plugins: [], features: [], auth_providers: providers }, 200);
        return jsonResponse({ detail: "not found" }, 404);
      }),
    );
  }

  it("offers a button for each login provider the server advertises", async () => {
    stubProviders([{ id: "idp", label: "Okta", login_url: "/api/auth/idp/login", password_login: true }]);
    renderLogin();
    const link = await screen.findByRole("link", { name: /Sign in with Okta/ });
    expect(link).toHaveAttribute("href", "/api/auth/idp/login");
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("shows no provider button when the server advertises none", async () => {
    stubProviders([]);
    renderLogin();
    await screen.findByLabelText("Email");
    expect(screen.queryByRole("link", { name: /Sign in with/ })).not.toBeInTheDocument();
  });

  it("hides the password form behind an owner sign-in link when a provider says passwords are refused", async () => {
    stubProviders([{ id: "idp", label: "Okta", login_url: "/api/auth/idp/login", password_login: false }]);
    renderLogin();
    await screen.findByRole("link", { name: /Sign in with Okta/ });
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Owner password sign-in" }));
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });
});

describe("Login", () => {
  beforeEach(() => {
    // Not logged in yet -- /api/auth/me should 401 on mount.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/auth/me")) {
          return jsonResponse({ detail: "Not authenticated" }, 401);
        }
        return jsonResponse({ detail: "not found" }, 404);
      }),
    );
  });

  it("renders email and password fields", async () => {
    renderLogin();

    expect(await screen.findByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it("shows an error when login fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/auth/me")) return jsonResponse({ detail: "Not authenticated" }, 401);
        if (url.endsWith("/api/auth/login")) return jsonResponse({ detail: "Invalid email or password" }, 401);
        return jsonResponse({ detail: "not found" }, 404);
      }),
    );

    renderLogin();
    fireEvent.change(await screen.findByLabelText(/email/i), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "wrong-password" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText(/invalid email or password/i)).toBeInTheDocument();
  });

  it("calls the login endpoint with the entered email/password on submit", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/auth/me")) return jsonResponse({ detail: "Not authenticated" }, 401);
      if (url.endsWith("/api/auth/login")) {
        return jsonResponse({ csrf_token: "test-csrf", expires_at: "2026-01-01T00:00:00Z", role: "owner" }, 200);
      }
      void init;
      return jsonResponse({ detail: "not found" }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);

    renderLogin();
    fireEvent.change(await screen.findByLabelText(/email/i), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "correct-password" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    // Successful login navigates Login away (it renders <Navigate>), so
    // assert on the mocked call directly rather than re-querying the DOM.
    await vi.waitFor(() => {
      const loginCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/api/auth/login"));
      expect(loginCall).toBeDefined();
      expect(JSON.parse((loginCall![1] as RequestInit).body as string)).toEqual({
        email: "user@example.com",
        password: "correct-password",
      });
    });
  });
});

describe("Signed out by timeout", () => {
  it("sends a signed-in user to the login page with an inactivity message when the API answers 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/auth/me"))
          return jsonResponse({ csrf_token: "t", expires_at: "x", role: "owner", email: "a@x.test" }, 200);
        if (url.endsWith("/api/capabilities"))
          return jsonResponse({ plugins: [], features: [], auth_providers: [] }, 200);
        return jsonResponse({ detail: "Signed out after a period of inactivity" }, 401);
      }),
    );
    function Probe() {
      const { isAuthenticated, loading } = useAuth();
      return (
        <>
          <button onClick={() => void apiFetch("/api/applications").catch(() => undefined)}>load</button>
          <span>{loading ? "loading" : isAuthenticated ? "in" : "out"}</span>
        </>
      );
    }
    render(
      <MemoryRouter>
        <AuthProvider>
          <Probe />
          <Login />
        </AuthProvider>
      </MemoryRouter>,
    );
    await screen.findByText("in");
    fireEvent.click(screen.getByRole("button", { name: "load" }));
    await screen.findByText("out");
    expect(await screen.findByText(/signed out after a period of inactivity/i)).toBeInTheDocument();
  });
});
