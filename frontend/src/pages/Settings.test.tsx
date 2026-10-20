import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { SettingsPage } from "./Settings";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <SettingsPage />
      </AuthProvider>
    </MemoryRouter>,
  );
}

describe("SettingsPage hash sections", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/auth/me")) {
          return jsonResponse({ csrf_token: "tok", expires_at: "2026-01-01T00:00:00Z", role: "owner" });
        }
        if (url.endsWith("/api/users")) return jsonResponse([]);
        if (url.endsWith("/api/tokens")) return jsonResponse([]);
        return jsonResponse({});
      }),
    );
  });

  it("auto-expands the Audit log section when the hash is #audit", async () => {
    renderAt("/settings#audit");

    await screen.findByRole("button", { name: /Audit log/ });
    expect(await screen.findByRole("link", { name: "Open audit log" })).toBeInTheDocument();
  });
});
