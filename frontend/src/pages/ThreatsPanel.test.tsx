import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ThreatsPanel, type ThreatOut } from "./ThreatsPanel";
import { offerDemoMethodology } from "../testMethodologies";
import { setAvailableMethodologies } from "../methodology";

function threat(overrides: Partial<ThreatOut>): ThreatOut {
  return {
    key: "PROC-S-01|process:API",
    rule_id: "PROC-S-01",
    element_kind: "component",
    element_id: "N-1",
    element_name: "API",
    element_type: "process",
    methodology: "STRIDE",
    category: "Spoofing",
    cia_impacts: ["Confidentiality", "Integrity"],
    title: "Callers can impersonate an identity to API",
    description: "Weak authentication lets an attacker impersonate a caller.",
    severity: "high",
    mitigations: ["Require authentication on every entry point."],
    cwe_refs: ["CWE-287"],
    attack_refs: ["T1078"],
    risk_factors: [],
    origin: "predefined",
    manual_threat_id: null,
    status: "open",
    note: "",
    dread: null,
    ...overrides,
  };
}

const THREATS: ThreatOut[] = [
  threat({}),
  threat({
    key: "STORE-I-01|data_store:DB",
    element_id: "N-2",
    element_name: "DB",
    element_type: "data_store",
    category: "InformationDisclosure",
    cia_impacts: ["Confidentiality"],
    title: "Sensitive data in DB can be read",
    severity: "critical",
    status: "mitigated",
  }),
];

describe("ThreatsPanel", () => {
  offerDemoMethodology();
  const fetchMock = vi.fn();
  // Opening a threat also asks whether AI is on (a GET), so look for the first write.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const firstWrite = (): [string, any] =>
    fetchMock.mock.calls.find(([, init]) => init && init.method && init.method !== "GET") as [string, any];

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
  });

  it("filters by status", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);
    expect(screen.getByText(/Callers can impersonate/)).toBeInTheDocument();
    expect(screen.getByText(/Sensitive data in DB/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter by status"), { target: { value: "mitigated" } });

    expect(screen.queryByText(/Callers can impersonate/)).not.toBeInTheDocument();
    expect(screen.getByText(/Sensitive data in DB/)).toBeInTheDocument();
  });

  it("filters the whole-model list by element, and honours a preset from the side panel", () => {
    const { rerender } = render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Filter by element"), { target: { value: "DB" } });
    expect(screen.queryByText(/Callers can impersonate/)).not.toBeInTheDocument();
    expect(screen.getByText(/Sensitive data in DB/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter by element"), { target: { value: "all" } });
    rerender(
      <ThreatsPanel
        applicationId="A"
        runId="R"
        threats={THREATS}
        onChanged={vi.fn()}
        presetElement={{ name: "API", nonce: 1 }}
      />,
    );
    expect(screen.getByText(/Callers can impersonate/)).toBeInTheDocument();
    expect(screen.queryByText(/Sensitive data in DB/)).not.toBeInTheDocument();
  });

  it("keeps the side-panel list compact: status lives in the expanded row, not a column", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} elementId="N-2" />);
    expect(screen.queryByLabelText(/Status for/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(/Sensitive data in DB/));
    expect(screen.getByLabelText(/Status for Sensitive data in DB/)).toBeInTheDocument();
  });

  it("scopes to one element when elementId is given", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} elementId="N-2" />);

    expect(screen.queryByText(/Callers can impersonate/)).not.toBeInTheDocument();
    expect(screen.getByText(/Sensitive data in DB/)).toBeInTheDocument();
  });

  it("shows mitigations and references when a row is expanded", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);

    fireEvent.click(screen.getByText(/Callers can impersonate/));

    expect(screen.getByText("Require authentication on every entry point.")).toBeInTheDocument();
    expect(screen.getByText(/CWE-287/)).toBeInTheDocument();
  });

  it("saves a status change to the API and notifies the owner", async () => {
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={onChanged} />);

    fireEvent.change(screen.getByLabelText(/Status for Callers can impersonate/), { target: { value: "mitigated" } });

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [url, init] = firstWrite();
    expect(url).toBe("/api/applications/A/runs/R/threats/status");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ threat_key: "PROC-S-01|process:API", status: "mitigated", note: "" });
  });

  it("shows an error and skips the refetch when saving fails", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ detail: "Unknown threat for this run" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={onChanged} />);

    fireEvent.change(screen.getByLabelText(/Status for Callers can impersonate/), { target: { value: "mitigated" } });

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("badges custom-rule and manual threats, and only manual ones can be deleted", async () => {
    const onChanged = vi.fn();
    const manual = threat({
      key: "MT-1|process:API",
      title: "Insider export",
      origin: "manual",
      manual_threat_id: "MT-1",
      category: null,
      mitigations: [],
    });
    const custom = threat({ key: "KB-1|process:API", title: "Badge cloning", origin: "custom_rule" });
    render(<ThreatsPanel applicationId="A" runId="R" threats={[manual, custom, THREATS[0]]} onChanged={onChanged} />);

    expect(screen.getByText("Manual")).toBeInTheDocument();
    expect(screen.getByText("Custom rule")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Badge cloning"));
    expect(screen.queryByText("Delete this threat")).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("Insider export"));
    expect(screen.getByText("None recorded.")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Delete this threat"));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [url, init] = firstWrite();
    expect(url).toBe("/api/applications/A/manual-threats/MT-1");
    expect(init.method).toBe("DELETE");
  });

  it("shows Add threat only when the owner provides a handler, including with no threats", () => {
    const onAdd = vi.fn();
    const { rerender } = render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);
    expect(screen.queryByRole("button", { name: "Add threat" })).not.toBeInTheDocument();

    rerender(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} onAddThreat={onAdd} />);
    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    expect(onAdd).toHaveBeenCalledTimes(1);

    rerender(<ThreatsPanel applicationId="A" runId="R" threats={[]} onChanged={vi.fn()} onAddThreat={onAdd} />);
    expect(screen.getByRole("button", { name: "Add threat" })).toBeInTheDocument();
  });

  it("ranks by risk, shows likelihood reasons and supporting findings, and filters by risk", () => {
    const risky = threat({
      key: "PROC-T-01|process:API",
      rule_id: "PROC-T-01",
      title: "Code of API can be tampered with",
      severity: "high",
      risk: "critical",
      likelihood: "almost_certain",
      likelihood_factors: ["exposed: directly reachable from an untrusted caller"],
      evidence: [{ finding_id: "F-1", title: "GHSA-1 in lodash@4.17.15", severity: "high", scope: "repository" }],
      evidence_total: 3,
    });
    render(
      <ThreatsPanel
        applicationId="APP-1"
        runId="RUN-1"
        threats={[threat({ risk: "low", likelihood: "rare" }), risky]}
        onChanged={() => undefined}
      />,
    );

    fireEvent.click(screen.getByText("Code of API can be tampered with"));
    expect(screen.getByText(/almost certain/)).toBeTruthy();
    expect(screen.getByText(/exposed: directly reachable/)).toBeTruthy();
    expect(screen.getByText("GHSA-1 in lodash@4.17.15")).toBeTruthy();
    expect(screen.getByText(/not confirmed in this component/)).toBeTruthy();
    expect(screen.getByText(/and 2 more, lower severity/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Filter by risk"), { target: { value: "low" } });
    expect(screen.queryByText("Code of API can be tampered with")).toBeNull();
  });
  it("offers Edit only on manual threats, and only when the owner provides a handler", () => {
    const onEdit = vi.fn();
    const manual = threat({ key: "MT-1|process:API", title: "Insider export", origin: "manual", manual_threat_id: "MT-1" });
    const { rerender } = render(
      <ThreatsPanel applicationId="A" runId="R" threats={[manual, THREATS[0]]} onChanged={vi.fn()} />,
    );
    fireEvent.click(screen.getByText("Insider export"));
    expect(screen.queryByText("Edit this threat")).not.toBeInTheDocument();

    rerender(
      <ThreatsPanel applicationId="A" runId="R" threats={[manual, THREATS[0]]} onChanged={vi.fn()} onEditThreat={onEdit} />,
    );
    fireEvent.click(screen.getByText("Edit this threat"));
    expect(onEdit).toHaveBeenCalledWith(manual);

    fireEvent.click(screen.getByText("Insider export")); // collapse it, then open a predefined one
    fireEvent.click(screen.getByText(/Callers can impersonate/));
    expect(screen.queryByText("Edit this threat")).not.toBeInTheDocument();
  });

  it("explains drawing, not scanning, when a blank model has no threats", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={[]} onChanged={vi.fn()} blankModel />);

    expect(screen.getByText(/generated for each component and connection you draw/)).toBeInTheDocument();
    expect(screen.queryByText(/repository scan/i)).not.toBeInTheDocument();
  });

  it("filters by methodology and category, scoped to the selected methodology's list", () => {
    const demo = threat({
      key: "DEMO-1|process:API",
      title: "API can be linked across sessions",
      methodology: "Demo",
      category: "Alpha",
      cia_impacts: ["Confidentiality"],
    });
    render(<ThreatsPanel applicationId="A" runId="R" threats={[...THREATS, demo]} onChanged={vi.fn()} />);

    fireEvent.change(screen.getByLabelText("Filter by methodology"), { target: { value: "Demo" } });
    expect(screen.queryByText(/Callers can impersonate/)).not.toBeInTheDocument();
    expect(screen.getByText(/API can be linked across sessions/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter by category"), { target: { value: "Beta" } });
    expect(screen.queryByText(/API can be linked across sessions/)).not.toBeInTheDocument();
  });

  it("offers only STRIDE and Custom in the methodology filter when no other methodology is available", () => {
    setAvailableMethodologies(null);
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);

    const options = within(screen.getByLabelText("Filter by methodology")).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(["All methodologies", "STRIDE", "Custom"]);
  });

  it("keeps a stored threat's methodology filterable and says which selected ones were not generated", () => {
    setAvailableMethodologies(null);
    const stale = threat({ key: "DEMO-1|process:API", title: "Stale threat", methodology: "Demo", category: "Alpha" });
    render(
      <ThreatsPanel
        applicationId="A" runId="R" threats={[...THREATS, stale]} onChanged={vi.fn()}
        unavailableMethodologies={["Demo"]}
      />,
    );

    expect(screen.getByText(/This model selects Demo, which is not available in this installation/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter by methodology"), { target: { value: "Demo" } });
    expect(screen.getByText(/Stale threat/)).toBeInTheDocument();
    expect(within(screen.getByLabelText("Filter by category")).getByRole("option", { name: "Alpha" })).toBeInTheDocument();
  });

  it("shows CIA impact badges for a threat's category", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);
    expect(screen.getAllByTitle("Confidentiality").length).toBeGreaterThan(0);
  });

  it("allows saving a note while the threat is still open", async () => {
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={onChanged} />);

    fireEvent.click(screen.getByText(/Callers can impersonate/));
    fireEvent.change(screen.getByLabelText(/Note/), { target: { value: "Investigating" } });
    expect(screen.getByRole("button", { name: "Save note" })).not.toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Save note" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [, init] = firstWrite();
    expect(JSON.parse(init.body)).toEqual({ threat_key: "PROC-S-01|process:API", status: "open", note: "Investigating" });
  });

  it("saves a DREAD score alongside the current status and note", async () => {
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={onChanged} />);

    fireEvent.click(screen.getByText(/Callers can impersonate/));
    fireEvent.change(screen.getByLabelText("Damage"), { target: { value: "8" } });
    fireEvent.click(screen.getByRole("button", { name: "Save DREAD score" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [, init] = firstWrite();
    const body = JSON.parse(init.body);
    expect(body.dread).toEqual({
      damage: 8,
      reproducibility: 5,
      exploitability: 5,
      affected_users: 5,
      discoverability: 5,
    });
  });

  it("collapses generic checklist items once something specific exists, and can expand them", () => {
    const list = [
      threat({ key: "SC-T08|a", rule_id: "SC-T08", title: "Credentials stored in ConfigMap", basis: "observed" }),
      threat({ key: "PROC-S-01|b", title: "Generic impersonation", basis: "generic", element_name: "B" }),
    ];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} />);

    expect(screen.getByText("Credentials stored in ConfigMap")).toBeInTheDocument();
    expect(screen.queryByText("Generic impersonation")).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("Show the generic checklist"));
    expect(screen.getByText("Generic impersonation")).toBeInTheDocument();
  });

  it("shows everything when every threat is generic, so a fresh hand-drawn model is not empty", () => {
    const list = [threat({ basis: "generic", title: "Only generic one" })];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} />);

    expect(screen.getByText("Only generic one")).toBeInTheDocument();
    expect(screen.queryByText("Show the generic checklist")).not.toBeInTheDocument();
  });

  it("never collapses the per-element list in the side panel", () => {
    const list = [
      threat({ key: "SC-T08|a", rule_id: "SC-T08", basis: "observed", element_id: "N-1" }),
      threat({ key: "PROC-S-01|b", title: "Generic impersonation", basis: "generic", element_id: "N-1" }),
    ];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} elementId="N-1" />);

    expect(screen.getByText("Generic impersonation")).toBeInTheDocument();
  });

  it("asks for a reason before accepting or dismissing a threat, and will not send without one", async () => {
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={onChanged} />);

    fireEvent.change(screen.getByLabelText(/Status for Callers can impersonate/), { target: { value: "not_applicable" } });
    expect(fetchMock).not.toHaveBeenCalled();
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Reason for this status"), { target: { value: "Internal only" } });
    fireEvent.click(save);

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(JSON.parse(firstWrite()[1].body)).toEqual({
      threat_key: "PROC-S-01|process:API", status: "not_applicable", note: "Internal only",
    });
  });

  it("does not ask again when the threat already has a note", async () => {
    const withNote = [threat({ note: "Already explained" })];
    render(<ThreatsPanel applicationId="A" runId="R" threats={withNote} onChanged={() => {}} />);

    fireEvent.change(screen.getByLabelText(/Status for Callers can impersonate/), { target: { value: "accepted" } });

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(screen.queryByLabelText("Reason for this status")).not.toBeInTheDocument();
  });

  it("shows how many threats are addressed and how many high-risk ones remain open", () => {
    const list = [
      threat({ key: "a", risk: "high", status: "open" }),
      threat({ key: "b", risk: "critical", status: "mitigated" }),
      threat({ key: "c", risk: "low", status: "accepted" }),
      threat({ key: "d", risk: "medium", status: "open" }),
    ];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} />);

    expect(screen.getByRole("progressbar", { name: "Threats addressed" })).toHaveAttribute("aria-valuenow", "50");
    expect(screen.getByText(/1 high or critical risk still open/)).toBeInTheDocument();
  });

  it("applies one status to several selected threats in a single request", async () => {
    const list = [threat({ key: "a", title: "First" }), threat({ key: "b", title: "Second" }), threat({ key: "c", title: "Third" })];
    const onChanged = vi.fn();
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={onChanged} />);

    fireEvent.click(screen.getByLabelText("Select First"));
    fireEvent.click(screen.getByLabelText("Select Third"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Reason for the selected threats"), { target: { value: "Fixed in PR 9" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [url, init] = firstWrite();
    expect(url).toBe("/api/applications/A/runs/R/threats/status/bulk");
    expect(JSON.parse(init.body)).toEqual({ threat_keys: ["a", "c"], status: "mitigated", note: "Fixed in PR 9" });
    expect(screen.queryByText("2 selected")).not.toBeInTheDocument();
  });

  it("requires a reason to bulk-accept, and can select everything listed", () => {
    const list = [threat({ key: "a", title: "First" }), threat({ key: "b", title: "Second" })];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} />);

    fireEvent.click(screen.getByLabelText("Select all listed threats"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Set selected threats to"), { target: { value: "accepted" } });

    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reason for the selected threats"), { target: { value: "Accepted by CISO" } });
    expect(screen.getByRole("button", { name: "Apply" })).toBeEnabled();
  });

  it("offers no bulk selection in the per-component side panel", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={() => {}} elementId="N-1" />);
    expect(screen.queryByLabelText("Select all listed threats")).not.toBeInTheDocument();
  });

  it("shows how to verify a fix and an example fix when a row is expanded", () => {
    const list = [
      threat({
        verification: ["Call it with no credentials and confirm 401."],
        fix_example: "kind: NetworkPolicy",
      }),
    ];
    render(<ThreatsPanel applicationId="A" runId="R" threats={list} onChanged={() => {}} />);

    fireEvent.click(screen.getByText("Callers can impersonate an identity to API"));

    expect(screen.getByText("How to verify")).toBeInTheDocument();
    expect(screen.getByText("Call it with no credentials and confirm 401.")).toBeInTheDocument();
    expect(screen.getByLabelText("Example fix")).toHaveTextContent("kind: NetworkPolicy");
  });

  it("omits the verification and example sections when a threat has none", () => {
    render(<ThreatsPanel applicationId="A" runId="R" threats={[threat({})]} onChanged={() => {}} />);
    fireEvent.click(screen.getByText("Callers can impersonate an identity to API"));

    expect(screen.queryByText("How to verify")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Example fix")).not.toBeInTheDocument();
  });
});
