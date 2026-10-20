import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ThreatKnowledgeBasePage } from "./ThreatKnowledgeBase";
import { offerDemoMethodology } from "../testMethodologies";

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

const RULES = [
  {
    id: "PROC-S-01",
    element_type: "process",
    methodology: "STRIDE",
    category: "Spoofing",
    title: "Callers can impersonate an identity to <element>",
    description: "Weak authentication.",
    severity: "high",
    mitigations: ["Require authentication on every entry point."],
    cwe_refs: ["CWE-287"],
    attack_refs: ["T1078"],
    applies_when: "Every element of this type",
  },
];

const ENTRIES = [
  {
    id: "KB-1", source: "custom", external_id: null, name: "Badge cloning", description: "d", tags: [], url: null,
    methodology: "STRIDE", category: null, severity: "high", mitigations: [], applies_to: "data_store", boundary_hint: "pci",
  },
  {
    id: "KB-2", source: "cwe", external_id: "CWE-79", name: "XSS", description: "d", tags: [], url: null,
    methodology: "STRIDE", category: null, severity: "medium", mitigations: [], applies_to: null, boundary_hint: null,
  },
];

describe("ThreatKnowledgeBasePage", () => {
  offerDemoMethodology();
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/threat-kb/rules")) return json(RULES);
        if (url.endsWith("/api/threat-kb")) return json(ENTRIES);
        return json({});
      }),
    );
  });

  it("lists pre-defined rules alongside custom and feed entries, with counts in the source dropdown", async () => {
    render(<ThreatKnowledgeBasePage />);

    expect(await screen.findByText("PROC-S-01")).toBeInTheDocument();
    expect(screen.getByText("Badge cloning")).toBeInTheDocument();
    expect(screen.getByText("XSS")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Pre-defined (1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Custom (1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "CWE (1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "MITRE ATT&CK (0)" })).toBeInTheDocument();
  });

  it("shows the entity, and the framework with its category underneath, for every kind of row", async () => {
    render(<ThreatKnowledgeBasePage />);

    const rule = (await screen.findByText("PROC-S-01")).closest("tr") as HTMLElement;
    expect(within(rule).getByText("Process")).toBeInTheDocument();
    expect(within(rule).getByText("STRIDE")).toBeInTheDocument();
    expect(within(rule).getByText("Spoofing")).toBeInTheDocument();

    // A custom entry with a STRIDE category shows it; one without shows no framework.
    const custom = screen.getByText("Badge cloning").closest("tr") as HTMLElement;
    expect(within(custom).queryByText("STRIDE")).not.toBeInTheDocument();

    // A feed entry is its own framework and has no category to show.
    const feed = screen.getByText("XSS").closest("tr") as HTMLElement;
    expect(within(feed).getByText("CWE", { selector: "div" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Entity" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Category" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Applies to" })).not.toBeInTheDocument();
  });

  it("shows STRIDE and its category for a custom entry that has one", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).endsWith("/api/threat-kb/rules")
          ? json([])
          : json([{ ...ENTRIES[0], category: "ElevationOfPrivilege" }]),
      ),
    );
    render(<ThreatKnowledgeBasePage />);

    const row = (await screen.findByText("Badge cloning")).closest("tr") as HTMLElement;
    expect(within(row).getByText("STRIDE")).toBeInTheDocument();
    expect(within(row).getByText("Elevation of privilege")).toBeInTheDocument();
  });

  it("filters by source and explains an empty feed", async () => {
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");
    const filter = screen.getByLabelText("Filter by source");

    fireEvent.change(filter, { target: { value: "custom" } });
    expect(screen.getByText("Badge cloning")).toBeInTheDocument();
    expect(screen.queryByText("PROC-S-01")).not.toBeInTheDocument();
    expect(screen.queryByText("XSS")).not.toBeInTheDocument();

    fireEvent.change(filter, { target: { value: "mitre_attack" } });
    expect(screen.getByText("No entries loaded for this feed yet.")).toBeInTheDocument();
  });

  it("expands a pre-defined rule to show its mitigations", async () => {
    render(<ThreatKnowledgeBasePage />);

    fireEvent.click(await screen.findByText("PROC-S-01"));

    expect(screen.getByText("Require authentication on every entry point.")).toBeInTheDocument();
  });

  it("shows what a custom threat applies to, and posts the generation fields when adding one", async () => {
    const fetchMock = vi.mocked(fetch);
    render(<ThreatKnowledgeBasePage />);

    const custom = (await screen.findByText("Badge cloning")).closest("tr") as HTMLElement;
    expect(within(custom).getByText("Data store")).toBeInTheDocument();
    expect(within(custom).getByText(/boundary contains "pci"/)).toBeInTheDocument();
    const feed = screen.getByText("XSS").closest("tr") as HTMLElement;
    expect(within(feed).getByText("Reference only")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Add custom threat" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Tailgating" } });
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "Follow someone in." } });
    fireEvent.change(screen.getByLabelText("Generate this threat automatically on"), { target: { value: "process" } });
    fireEvent.change(screen.getByLabelText(/Only where the trust boundary contains/), { target: { value: " dmz " } });
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "low" } });
    fireEvent.change(screen.getByLabelText("Suggested mitigations (one per line)"), {
      target: { value: "Badge readers\n\n Guard " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true));
    const body = JSON.parse(String(fetchMock.mock.calls.find(([, init]) => init?.method === "POST")?.[1]?.body));
    expect(body).toMatchObject({
      name: "Tailgating",
      applies_to: "process",
      boundary_hint: "dmz",
      methodology: "STRIDE",
      category: null,
      severity: "low",
      mitigations: ["Badge readers", "Guard"],
    });
  });

  it("hides the boundary field for a reference-only threat and posts applies_to null", async () => {
    const fetchMock = vi.mocked(fetch);
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    fireEvent.click(screen.getByRole("button", { name: "Add custom threat" }));

    expect(screen.queryByLabelText(/Only where the trust boundary contains/)).not.toBeInTheDocument();
    expect(screen.getByText(/attach this threat to specific components by hand/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Note" } });
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "d" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true));
    const body = JSON.parse(String(fetchMock.mock.calls.find(([, init]) => init?.method === "POST")?.[1]?.body));
    expect(body.applies_to).toBeNull();
    expect(body.boundary_hint).toBeNull();
  });

  it("scopes the category picker to the chosen methodology and posts it", async () => {
    const fetchMock = vi.mocked(fetch);
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    fireEvent.click(screen.getByRole("button", { name: "Add custom threat" }));
    const modal = screen.getByRole("dialog");

    within(modal).getByLabelText("Name");  // Ensure we can find the modal
    fireEvent.change(within(modal).getByLabelText("Name"), { target: { value: "Rogue admin" } });
    fireEvent.change(within(modal).getByLabelText("Description"), { target: { value: "d" } });
    fireEvent.change(within(modal).getByLabelText("Category (optional)"), { target: { value: "Tampering" } });
    fireEvent.change(within(modal).getByLabelText("Methodology"), { target: { value: "Demo" } });

    expect(within(modal).getByLabelText("Category (optional)")).toHaveValue("");
    expect(within(modal).getByRole("option", { name: "Beta" })).toBeInTheDocument();

    fireEvent.change(within(modal).getByLabelText("Category (optional)"), { target: { value: "Beta" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true));
    const body = JSON.parse(String(fetchMock.mock.calls.find(([, init]) => init?.method === "POST")?.[1]?.body));
    expect(body.methodology).toBe("Demo");
    expect(body.category).toBe("Beta");
  });

  it("shows 'Showing N of M' count with all filters active", async () => {
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    expect(screen.getByText("Showing 3 of 3")).toBeInTheDocument();
  });

  it("filters by search on ID, name, and description (case-insensitive)", async () => {
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    const searchBox = screen.getByLabelText("Search threats");
    fireEvent.change(searchBox, { target: { value: "badge" } });

    expect(screen.getByText("Badge cloning")).toBeInTheDocument();
    expect(screen.queryByText("PROC-S-01")).not.toBeInTheDocument();
    expect(screen.queryByText("XSS")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();

    fireEvent.change(searchBox, { target: { value: "weak" } });
    expect(screen.getByText("PROC-S-01")).toBeInTheDocument();
    expect(screen.queryByText("Badge cloning")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
  });

  it("filters by methodology", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/threat-kb/rules")) {
          return json([{ ...RULES[0], methodology: "STRIDE" }]);
        }
        return json([
          { ...ENTRIES[0], methodology: "STRIDE" },
          { ...ENTRIES[1], methodology: "Demo" },
        ]);
      }),
    );
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    const methodologyFilter = screen.getByLabelText("Methodology");
    fireEvent.change(methodologyFilter, { target: { value: "Demo" } });

    expect(screen.getByText("XSS")).toBeInTheDocument();
    expect(screen.queryByText("PROC-S-01")).not.toBeInTheDocument();
    expect(screen.queryByText("Badge cloning")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
  });

  it("filters by entity", async () => {
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    const entityFilter = screen.getByLabelText("Entity");
    fireEvent.change(entityFilter, { target: { value: "data_store" } });

    expect(screen.getByText("Badge cloning")).toBeInTheDocument();
    expect(screen.queryByText("PROC-S-01")).not.toBeInTheDocument();
    expect(screen.queryByText("XSS")).not.toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 3")).toBeInTheDocument();
  });

  it("shows 'No threats match these filters' message with a clear filters button", async () => {
    render(<ThreatKnowledgeBasePage />);
    await screen.findByText("PROC-S-01");

    const searchBox = screen.getByLabelText("Search threats");
    fireEvent.change(searchBox, { target: { value: "nonexistent" } });

    expect(screen.getByText("No threats match these filters.")).toBeInTheDocument();
    const clearButton = screen.getByRole("button", { name: "Clear filters" });
    expect(clearButton).toBeInTheDocument();

    fireEvent.click(clearButton);
    expect(screen.queryByText("No threats match these filters.")).not.toBeInTheDocument();
    expect(screen.getByText("PROC-S-01")).toBeInTheDocument();
    expect(screen.getByText("Badge cloning")).toBeInTheDocument();
    expect(screen.getByText("XSS")).toBeInTheDocument();
  });
});
