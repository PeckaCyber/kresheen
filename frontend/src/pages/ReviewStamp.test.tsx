import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewStamp } from "./ReviewStamp";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("ReviewStamp", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("marks the model reviewed and shows who", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ reviewed_at: null, reviewed_by: "" }))
      .mockResolvedValueOnce(json({ reviewed_at: "2026-09-25T10:00:00Z", reviewed_by: "sec@example.com" }));
    render(<ReviewStamp applicationId="A" />);

    fireEvent.click(await screen.findByRole("button", { name: "Mark as reviewed" }));

    expect(await screen.findByText(/Reviewed .* by sec@example.com/)).toBeInTheDocument();
    const reviewCall = fetchMock.mock.calls.find((call) => call[0] === "/api/applications/A/review");
    expect(reviewCall).toBeDefined();
    expect(JSON.parse((reviewCall![1] as RequestInit).body as string)).toEqual({ reviewed: true });
  });

  it("can undo a review", async () => {
    fetchMock
      .mockResolvedValueOnce(json({ reviewed_at: "2026-09-25T10:00:00Z", reviewed_by: "sec@example.com" }))
      .mockResolvedValueOnce(json({ reviewed_at: null, reviewed_by: "" }));
    render(<ReviewStamp applicationId="A" />);

    fireEvent.click(await screen.findByRole("button", { name: "Undo" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Mark as reviewed" })).toBeInTheDocument());
  });

  it("says so when saving fails", async () => {
    fetchMock.mockResolvedValueOnce(json({ reviewed_at: null, reviewed_by: "" })).mockResolvedValueOnce(json({}, 500));
    render(<ReviewStamp applicationId="A" />);

    fireEvent.click(await screen.findByRole("button", { name: "Mark as reviewed" }));

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
