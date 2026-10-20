import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AddThreatModal, type ElementChoice } from "./AddThreatModal";
import { offerDemoMethodology } from "../testMethodologies";
import { setAvailableMethodologies } from "../methodology";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const ELEMENTS: ElementChoice[] = [
  { kind: "component", id: "N-1", label: "API" },
  { kind: "component", id: "N-2", label: "Orders DB" },
  { kind: "flow", id: "E-1", label: "API -> Orders DB" },
];

const KB = [
  {
    id: "KB-1",
    source: "custom",
    name: "Badge cloning at {name}",
    description: "Cloned badges grant access.",
    severity: "high",
    methodology: "STRIDE",
    category: "Spoofing",
    mitigations: ["Rotate badges.", "Use MFA."],
  },
];

function renderModal(props: Partial<React.ComponentProps<typeof AddThreatModal>> = {}) {
  const onCreated = vi.fn();
  const onHide = vi.fn();
  render(
    <AddThreatModal
      show
      onHide={onHide}
      applicationId="A"
      runId="R"
      elements={ELEMENTS}
      onCreated={onCreated}
      {...props}
    />,
  );
  return { onCreated, onHide };
}

describe("AddThreatModal", () => {
  offerDemoMethodology();
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) =>
      String(input).endsWith("/api/threat-kb") ? json(KB) : json({}),
    );
    vi.stubGlobal("fetch", fetchMock);
  });

  it("preselects the given element and groups components and data flows", async () => {
    renderModal({ initialElementId: "N-2" });

    expect(await screen.findByRole("option", { name: "None, write my own" })).toBeInTheDocument();
    expect(screen.getByLabelText("Element")).toHaveValue("N-2");
    expect(screen.getByRole("group", { name: "Components" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Data flows" })).toBeInTheDocument();
  });

  it("prefills from a knowledge base entry, substituting the element name, and posts the manual threat", async () => {
    const { onCreated, onHide } = renderModal({ initialElementId: "N-1" });

    fireEvent.change(await screen.findByLabelText(/Start from a knowledge base entry/), { target: { value: "KB-1" } });

    expect(screen.getByLabelText("Title")).toHaveValue("Badge cloning at API");
    expect(screen.getByLabelText("Severity")).toHaveValue("high");
    expect(screen.getByLabelText("Methodology")).toHaveValue("STRIDE");
    expect(screen.getByLabelText(/^Category/)).toHaveValue("Spoofing");
    expect(screen.getByLabelText(/Mitigations/)).toHaveValue("Rotate badges.\nUse MFA.");

    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(onHide).toHaveBeenCalled();
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post?.[0]).toBe("/api/applications/A/runs/R/manual-threats");
    expect(JSON.parse(post?.[1].body)).toEqual({
      element_kind: "component",
      element_id: "N-1",
      kb_entry_id: "KB-1",
      title: "Badge cloning at API",
      description: "Cloned badges grant access.",
      severity: "high",
      methodology: "STRIDE",
      category: "Spoofing",
      mitigations: ["Rotate badges.", "Use MFA."],
    });
  });

  it("sends a flow element with its kind, null category, and no kb entry for a hand-written threat", async () => {
    renderModal();

    fireEvent.change(await screen.findByLabelText("Element"), { target: { value: "E-1" } });
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Replay of orders" } });
    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([, i]) => i?.method === "POST")).toBe(true));
    const body = JSON.parse(fetchMock.mock.calls.find(([, i]) => i?.method === "POST")?.[1].body);
    expect(body).toMatchObject({
      element_kind: "flow",
      element_id: "E-1",
      kb_entry_id: null,
      methodology: "STRIDE",
      category: null,
      mitigations: [],
    });
  });

  it("scopes the category picker to the selected methodology, resetting the choice", async () => {
    renderModal();
    await screen.findByLabelText("Element");

    fireEvent.change(screen.getByLabelText(/^Category/), { target: { value: "Tampering" } });
    fireEvent.change(screen.getByLabelText("Methodology"), { target: { value: "Demo" } });

    expect(screen.getByLabelText(/^Category/)).toHaveValue("");
    expect(screen.getByRole("option", { name: "Alpha" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Tampering" })).not.toBeInTheDocument();
  });

  it("offers only STRIDE and Custom when no other methodology is available", async () => {
    setAvailableMethodologies(null);
    renderModal();
    await screen.findByLabelText("Element");

    const options = within(screen.getByLabelText("Methodology")).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(["STRIDE", "Custom"]);
  });

  it("keeps the dialog open and shows the server's message when saving fails", async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) =>
      init?.method === "POST"
        ? json({ detail: "Unknown component in this run" }, 404)
        : String(input).endsWith("/api/threat-kb")
          ? json(KB)
          : json({}),
    );
    const { onCreated, onHide } = renderModal();

    fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "T" } });
    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));

    expect(await screen.findByText("Unknown component in this run")).toBeInTheDocument();
    expect(onCreated).not.toHaveBeenCalled();
    expect(onHide).not.toHaveBeenCalled();
  });
  it("edits a manual threat: prefilled, no element or KB pickers, PATCHes the changes", async () => {
    const editing = {
      manual_threat_id: "MT-1",
      element_name: "API",
      title: "Insider export",
      description: "old",
      severity: "low",
      methodology: "STRIDE" as const,
      category: "Tampering",
      mitigations: ["A.", "B."],
    };
    const { onCreated, onHide } = renderModal({ editing, elements: [] });

    expect(await screen.findByText("Edit threat")).toBeInTheDocument();
    expect(screen.queryByLabelText("Element")).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Start from a knowledge base entry/)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Title")).toHaveValue("Insider export");
    expect(screen.getByLabelText(/Mitigations/)).toHaveValue("A.\nB.");

    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Insider exports data" } });
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(onHide).toHaveBeenCalled();
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
    expect(call?.[0]).toBe("/api/applications/A/runs/R/manual-threats/MT-1");
    expect(JSON.parse(call?.[1].body)).toEqual({
      title: "Insider exports data",
      description: "old",
      severity: "critical",
      methodology: "STRIDE",
      category: "Tampering",
      mitigations: ["A.", "B."],
    });
  });
});
