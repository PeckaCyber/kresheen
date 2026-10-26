import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiTokensSection } from "./ApiTokensSection";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const existing = {
  id: "TOKEN-1",
  name: "old",
  prefix: "pck_abcd",
  created_at: "2026-09-24T00:00:00Z",
  last_used_at: null,
};

describe("ApiTokensSection", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("lists tokens by prefix, never a secret", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([existing]));
    render(<ApiTokensSection />);
    fireEvent.click(screen.getByRole("button", { name: /API tokens/ }));

    expect(await screen.findByText("old")).toBeInTheDocument();
    expect(screen.getByText("pck_abcd...")).toBeInTheDocument();
    expect(screen.getByText("never")).toBeInTheDocument();
  });

  it("shows a newly created secret once", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ ...existing, id: "TOKEN-2", name: "ci", secret: "pck_fullsecret" }))
      .mockResolvedValueOnce(jsonResponse([{ ...existing, id: "TOKEN-2", name: "ci" }]));
    render(<ApiTokensSection />);
    fireEvent.click(screen.getByRole("button", { name: /API tokens/ }));

    fireEvent.change(screen.getByLabelText("Token name"), { target: { value: "ci" } });
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));

    expect(await screen.findByTestId("new-token-secret")).toHaveTextContent("pck_fullsecret");
  });

  it("revokes a token and reloads", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([existing]))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(jsonResponse([]));
    render(<ApiTokensSection />);
    fireEvent.click(screen.getByRole("button", { name: /API tokens/ }));

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));

    await vi.waitFor(() => expect(screen.queryByText("old")).not.toBeInTheDocument());
    expect(fetchMock.mock.calls[1][0]).toBe("/api/tokens/TOKEN-1");
  });

  it("defaults to 90 days and sends null only when never is chosen", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ ...existing, id: "TOKEN-3", name: "ci", secret: "pck_x" }))
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({ ...existing, id: "TOKEN-4", name: "plain", secret: "pck_y" }))
      .mockResolvedValueOnce(jsonResponse([]));
    render(<ApiTokensSection />);
    fireEvent.click(screen.getByRole("button", { name: /API tokens/ }));

    fireEvent.change(screen.getByLabelText("Token name"), { target: { value: "ci" } });
    expect(screen.getByLabelText("Token expiry")).toHaveValue("90");
    expect(screen.queryByText(/never expires stays valid/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));
    await vi.waitFor(() =>
      expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ name: "ci", expires_in_days: 90 }),
    );

    await screen.findByTestId("new-token-secret");
    fireEvent.change(screen.getByLabelText("Token name"), { target: { value: "plain" } });
    fireEvent.change(screen.getByLabelText("Token expiry"), { target: { value: "never" } });
    expect(screen.getByText(/never expires stays valid/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Create token" }));
    await vi.waitFor(() =>
      expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({ name: "plain", expires_in_days: null }),
    );
  });

  it("shows when a token expires and flags an expired one", async () => {
    const future = new Date(Date.now() + 5 * 86400000).toISOString();
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        { ...existing, id: "A", name: "soon", expires_at: future },
        { ...existing, id: "B", name: "gone", expires_at: "2020-01-01T00:00:00Z" },
        existing,
      ]),
    );
    render(<ApiTokensSection />);
    fireEvent.click(screen.getByRole("button", { name: /API tokens/ }));

    expect(await screen.findByText("expired")).toBeInTheDocument();
    expect(screen.getByText("never expires")).toBeInTheDocument();
    expect(screen.getByText(new Date(future).toLocaleDateString())).toBeInTheDocument();
  });
});
