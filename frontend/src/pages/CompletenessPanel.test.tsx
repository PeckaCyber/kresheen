import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CompletenessPanel, type CompletenessItem, type CompletenessOut } from "./CompletenessPanel";

function item(overrides: Partial<CompletenessItem>): CompletenessItem {
  return {
    id: "authenticates_callers|component:1",
    check: "authenticates_callers",
    element_kind: "component",
    element_id: "N-1",
    element_name: "Portal",
    message: "Does Portal require callers to authenticate?",
    why: "If it does, the likelihood of impersonation drops.",
    impact: "high",
    fix: {
      property_key: "authenticates_callers",
      kind: "bool",
      options: [],
      suggested_value: null,
      suggestion_reason: "",
      alternative: null,
    },
    ...overrides,
  };
}

function out(items: CompletenessItem[], score: number | null = 40): CompletenessOut {
  return { score, answered: 2, total: 5, items };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("CompletenessPanel", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows the score and what each question changes", async () => {
    fetchMock.mockResolvedValue(json(out([item({})])));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    expect(await screen.findByText("Does Portal require callers to authenticate?")).toBeInTheDocument();
    expect(screen.getByText(/2 of 5 facts that shape your threats are stated/)).toBeInTheDocument();
    expect(screen.getByText("If it does, the likelihood of impersonation drops.")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Model completeness" })).toHaveAttribute("aria-valuenow", "40");
  });

  it("stores a yes/no answer by merging one property, then refreshes and notifies the page", async () => {
    const onAnswered = vi.fn();
    fetchMock
      .mockResolvedValueOnce(json(out([item({})])))
      .mockResolvedValueOnce(json({ element_key: "process:Portal", properties: { authenticates_callers: true } }))
      .mockResolvedValueOnce(json(out([], 60)));
    render(<CompletenessPanel applicationId="A" runId="R" onAnswered={onAnswered} />);

    fireEvent.click(await screen.findByRole("button", { name: /^Yes:/ }));

    await waitFor(() => expect(onAnswered).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/applications/A/runs/R/element-properties");
    expect((init as RequestInit).method).toBe("PATCH");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      element_kind: "component",
      element_id: "N-1",
      properties: { authenticates_callers: true },
    });
    expect(await screen.findByText(/Nothing left to state/)).toBeInTheDocument();
  });

  it("shows a suggestion drawn from the flow label, but never applies it on its own", async () => {
    const flow = item({
      id: "encrypted_in_transit|flow:f",
      check: "encrypted_in_transit",
      element_kind: "flow",
      element_id: "f",
      message: "Is User -> Portal encrypted in transit?",
      fix: {
        property_key: "is_encrypted",
        kind: "bool",
        options: [],
        suggested_value: true,
        suggestion_reason: 'the label says "HTTPS"',
        alternative: null,
      },
    });
    fetchMock.mockResolvedValue(json(out([flow])));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    expect(await screen.findByText(/Suggested yes: the label says "HTTPS"/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1); // only the initial load: nothing was saved
  });

  it("offers a data classification and a way to say there is no sensitive data", async () => {
    const store = item({
      id: "data_classification|component:2",
      check: "data_classification",
      element_id: "N-2",
      element_name: "DB",
      message: "What kind of data does DB hold?",
      fix: {
        property_key: "data_classification",
        kind: "text",
        options: ["PII", "PHI"],
        suggested_value: null,
        suggestion_reason: "",
        alternative: { key: "no_sensitive_data", value: true, label: "Holds no sensitive data" },
      },
    });
    fetchMock
      .mockResolvedValueOnce(json(out([store])))
      .mockResolvedValueOnce(json({ element_key: "data_store:DB", properties: { no_sensitive_data: true } }))
      .mockResolvedValueOnce(json(out([])));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    fireEvent.click(await screen.findByText("Holds no sensitive data"));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string).properties).toEqual({
      no_sensitive_data: true,
    });
  });

  it("lists structural notes without controls, and says so when there is nothing to ask", async () => {
    const note = item({
      id: "no_boundaries|model",
      check: "no_boundaries",
      element_kind: "model",
      element_id: null,
      message: "No trust boundaries are drawn.",
      fix: null,
    });
    fetchMock.mockResolvedValue(json(out([note], null)));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    expect(await screen.findByText("No trust boundaries are drawn.")).toBeInTheDocument();
    expect(screen.getByText(/no component facts to ask about yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Yes/ })).not.toBeInTheDocument();
  });

  it("shows only the first few in a long group until asked for all", async () => {
    const many = Array.from({ length: 7 }, (_, i) => item({ id: `x|${i}`, message: `Question ${i}` }));
    fetchMock.mockResolvedValue(json(out(many)));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    await screen.findByText("Question 0");
    expect(screen.queryByText("Question 6")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Show all 7"));
    expect(screen.getByText("Question 6")).toBeInTheDocument();
  });

  it("reports a failed save without losing the list", async () => {
    fetchMock
      .mockResolvedValueOnce(json(out([item({})])))
      .mockResolvedValueOnce(json({ detail: "'x' is not a property" }, 422));
    render(<CompletenessPanel applicationId="A" runId="R" />);

    fireEvent.click(await screen.findByRole("button", { name: /^No:/ }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Does Portal require callers to authenticate?")).toBeInTheDocument();
  });
});
