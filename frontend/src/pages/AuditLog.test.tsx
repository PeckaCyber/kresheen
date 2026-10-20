import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuditLogPage } from "./AuditLog";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("AuditLogPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("lists events with who, action, target and channel", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        {
          id: "AUD-1",
          at: "2026-09-24T10:00:00Z",
          user_email: "a@x.com",
          action: "POST /api/applications/{application_id}/runs",
          subject: { application_id: "APP-1" },
          status_code: 200,
          via: "api_token",
          client_ip: null,
        },
      ]),
    );
    render(<AuditLogPage />);

    expect(await screen.findByText("a@x.com")).toBeInTheDocument();
    expect(screen.getByText("APP-1")).toBeInTheDocument();
    expect(screen.getByText("API token")).toBeInTheDocument();
  });

  it("explains a forbidden response", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: "Owner role required" }, 403));
    render(<AuditLogPage />);
    expect(await screen.findByText(/owners only/)).toBeInTheDocument();
  });
});
