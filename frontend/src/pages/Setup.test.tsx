import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { Setup } from "./Setup";

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderSetup() {
  return render(
    <MemoryRouter initialEntries={["/setup"]}>
      <AuthProvider>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="/login" element={<div>login page</div>} />
          <Route path="/dashboard" element={<div>dashboard page</div>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

function stubServer(needed: boolean) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/auth/me")) return jsonResponse({ detail: "Not authenticated" }, 401);
    if (url.endsWith("/api/auth/setup") && (init?.method ?? "GET") === "GET") return jsonResponse({ needed }, 200);
    if (url.endsWith("/api/auth/setup")) return jsonResponse({ ok: true }, 201);
    if (url.endsWith("/api/auth/login"))
      return jsonResponse(
        { csrf_token: "c", expires_at: "2099-01-01T00:00:00Z", role: "owner", email: "me@example.com" },
        200,
      );
    return jsonResponse({ detail: "not found" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("Setup", () => {
  it("creates the owner with the token from the link, signs in and clears the token from the address", async () => {
    window.history.replaceState(null, "", "/setup#token=abc123");
    const fetchMock = stubServer(true);
    renderSetup();

    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a-long-password" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "a-long-password" } });
    expect(window.location.hash).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByText("dashboard page")).toBeInTheDocument();
    const setupCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).endsWith("/api/auth/setup") && init?.method === "POST",
    );
    expect(JSON.parse(String(setupCall?.[1]?.body))).toEqual({
      token: "abc123",
      email: "me@example.com",
      password: "a-long-password",
    });
  });

  it("refuses mismatched passwords before calling the server", async () => {
    window.history.replaceState(null, "", "/setup#token=abc123");
    const fetchMock = stubServer(true);
    renderSetup();

    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a-long-password" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "another-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));

    expect(await screen.findByText("The passwords do not match.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("sends the user to sign in when setup does not apply", async () => {
    window.history.replaceState(null, "", "/setup#token=abc123");
    stubServer(false);
    renderSetup();
    await waitFor(() => expect(screen.getByText("login page")).toBeInTheDocument());
  });

  it("sends the user to sign in when the link has no token", async () => {
    stubServer(true);
    renderSetup();
    await waitFor(() => expect(screen.getByText("login page")).toBeInTheDocument());
  });
});
