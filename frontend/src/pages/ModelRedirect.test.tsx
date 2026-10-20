import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ModelRedirectPage } from "./ModelRedirect";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function renderAt(applicationId: string) {
  return render(
    <MemoryRouter initialEntries={[`/models/${applicationId}`]}>
      <Routes>
        <Route path="/models/:applicationId" element={<ModelRedirectPage />} />
        <Route path="/applications/:applicationId/runs/:runId" element={<div>run page</div>} />
        <Route path="/applications" element={<div>threat models list</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ModelRedirectPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("redirects to the latest completed run", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        { id: "RUN-1", status: "completed", started_at: "2026-09-01T00:00:00Z" },
        { id: "RUN-2", status: "failed", started_at: "2026-09-10T00:00:00Z" },
        { id: "RUN-3", status: "completed", started_at: "2026-09-20T00:00:00Z" },
      ]),
    );
    renderAt("APP-1");

    expect(await screen.findByText("run page")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/applications/APP-1/runs", expect.anything());
  });

  it("redirects to the latest run when none completed, so a failed first run shows its tools", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: "RUN-1", status: "failed", started_at: "2026-09-01T00:00:00Z" }]));
    renderAt("APP-2");

    expect(await screen.findByText("run page")).toBeInTheDocument();
  });

  it("shows the same not-run-yet message when the application has no runs at all", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    renderAt("APP-3");

    expect(await screen.findByText("This model has not been run yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to threat models" })).toHaveAttribute("href", "/applications");
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: "RUN-9", status: "completed" }));
    fireEvent.click(screen.getByRole("button", { name: "Run this model now" }));
    expect(await screen.findByText("run page")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith("/api/applications/APP-3/runs", expect.objectContaining({ method: "POST" }));
  });
});
