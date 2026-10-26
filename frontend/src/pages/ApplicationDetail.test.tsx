import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApplicationDetailPage } from "./ApplicationDetail";

// @xyflow/react needs ResizeObserver, which jsdom doesn't provide.
if (!("ResizeObserver" in window)) {
  (window as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const APP = {
  id: "APP-1",
  name: "Sample Shop",
  description: "",
  owner: "",
  reviewer: "",
  contributors: [],
  methodologies: ["STRIDE"],
  group_id: "GRP-1",
  reviewed_at: null,
  reviewed_by: "",
};
const GROUPS = { groups: [{ id: "GRP-1", name: "Payments" }] };
const RUN = {
  id: "RUN-1",
  status: "completed",
  error_message: null,
  data_source_config_ids: ["DS-1"],
  source_results: [],
};
const DFD = {
  nodes: [
    {
      id: "N-1",
      name: "Web",
      type: "process",
      trust_boundary: null,
      worst_severity: null,
      open_finding_count: 0,
      is_manual: false,
      boundary_overridden: false,
      position_x: null,
      position_y: null,
    },
  ],
  edges: [],
  boundaries: [],
};
const THREATS = {
  threats: [
    {
      key: "T-1",
      rule_id: "R-1",
      element_kind: "component",
      element_id: "N-1",
      element_name: "Web",
      element_type: "process",
      methodology: "STRIDE",
      category: "Spoofing",
      cia_impacts: [],
      title: "Spoofing of Web",
      description: "desc",
      severity: "high",
      risk: "high",
      basis: "generic",
      mitigations: [],
      cwe_refs: [],
      attack_refs: [],
      risk_factors: [],
      origin: "predefined",
      manual_threat_id: null,
      status: "open",
      note: "",
      dread: null,
    },
  ],
  summary: { total: 1, by_status: { open: 1 }, open_by_severity: { high: 1 }, open_by_risk: { high: 1 } },
  coverage_gaps: [],
  doc_conflicts: [],
};
const ACTION_PLAN = {
  actions: [
    {
      id: "A-1",
      text: "Add authentication",
      score: 10,
      max_risk: "high",
      basis: "generic",
      threat_count: 1,
      element_count: 1,
      elements: ["Web"],
      cwe_refs: [],
      threat_keys: ["T-1"],
      status: "todo",
      note: "",
    },
  ],
  summary: { total: 1, by_status: { todo: 1 }, open_threats_covered: 1 },
};
const COMPLETENESS = { score: 40, answered: 2, total: 5, items: [] };
const COMPLIANCE = {
  framework: { id: "f", name: "Framework", version: "1" },
  available_frameworks: [{ id: "f", name: "Framework", version: "1" }],
  summary: { controls_total: 0, controls_with_threats: 0, open: 0, accepted: 0, addressed: 0, unmapped_threats: 0 },
  controls: [],
  disclaimer: "",
};

function routeFor(url: string): unknown {
  if (/\/runs\/RUN-1\/dfd/.test(url)) return DFD;
  if (/\/runs\/RUN-1\/findings/.test(url)) return [];
  if (/\/runs\/RUN-1\/sbom/.test(url)) return null;
  if (url.endsWith("/runs/RUN-1/threats")) return THREATS;
  if (/\/runs\/RUN-1\/diff/.test(url)) return { current_run_id: "RUN-1", previous_run_id: null };
  if (/\/runs\/RUN-1\/attack-paths/.test(url)) return { paths: [] };
  if (/\/runs\/RUN-1\/action-plan/.test(url)) return ACTION_PLAN;
  if (/\/runs\/RUN-1\/completeness/.test(url)) return COMPLETENESS;
  if (/\/runs\/RUN-1\/compliance/.test(url)) return COMPLIANCE;
  if (url.endsWith("/runs/RUN-1")) return RUN;
  if (url.endsWith("/runs")) return [{ id: "RUN-1", status: "completed", started_at: "2026-09-20T10:00:00Z" }];
  if (/\/staleness/.test(url))
    return { stale: false, new_data_source_ids: [], changed_data_source_ids: [], removed_data_source_ids: [] };
  if (/\/diagrams\/[^/]+\/layout/.test(url)) return [];
  if (/\/diagrams/.test(url)) return [{ id: "DIAG-1", name: "Main" }];
  if (/\/data-sources/.test(url)) return [];
  if (/\/api\/groups/.test(url)) return GROUPS;
  if (url.endsWith("/api/applications/APP-1")) return APP;
  if (/\/api\/threat-kb\/property-specs/.test(url)) return {};
  return {};
}

describe("ApplicationDetailPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      return Promise.resolve(json(routeFor(url)));
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  function open(path = "/applications/APP-1/runs/RUN-1") {
    render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/applications/:applicationId/runs/:runId" element={<ApplicationDetailPage />} />
          <Route path="/applications/:applicationId/runs/:runId/:tab" element={<ApplicationDetailPage />} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it("shows a plain not-found page with a way back when the API answers 404", async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      return Promise.resolve(url.endsWith("/runs/RUN-1") ? json({ detail: "Not found" }, 404) : json(routeFor(url)));
    });
    open();
    const page = await screen.findByTestId("model-not-found");
    expect(page).toHaveTextContent("This threat model does not exist or you do not have access to it.");
    expect(screen.getByRole("link", { name: "Back to Threat models" })).toHaveAttribute("href", "/applications");
    expect(screen.queryByText(/Failed to load/)).toBeNull();
  });

  it("keeps the generic message for other load errors", async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      return Promise.resolve(url.endsWith("/runs/RUN-1") ? json({ detail: "boom" }, 500) : json(routeFor(url)));
    });
    open();
    expect(await screen.findByText("Failed to load this threat model run.")).toBeInTheDocument();
    expect(screen.queryByTestId("model-not-found")).toBeNull();
  });

  it("shows the application's name in the header", async () => {
    open();
    expect(await screen.findByRole("heading", { name: "Sample Shop" })).toBeInTheDocument();
  });

  it("warns when a source was read but a check (the vulnerability scan) did not run", async () => {
    const partial = {
      ...RUN,
      source_results: [
        {
          data_source_id: "DS-1",
          type: "github_repository",
          status: "analysed",
          component_count: 3,
          vulnerability_count: 0,
          message: "",
          warnings: [
            "Grype is not installed on the server, so dependencies were not checked for known vulnerabilities.",
          ],
        },
      ],
    };
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      return Promise.resolve(json(url.endsWith("/runs/RUN-1") ? partial : routeFor(url)));
    });
    open();
    const banner = await screen.findByTestId("partly-analysed-banner");
    expect(banner).toHaveTextContent("incomplete");
    expect(banner).toHaveTextContent("Grype is not installed");
    expect(screen.queryByTestId("not-analysed-banner")).toBeNull();
  });

  it("shows no incomplete-result banner for a fully analysed run", async () => {
    open();
    await screen.findByRole("heading", { name: "Sample Shop" });
    expect(screen.queryByTestId("partly-analysed-banner")).toBeNull();
  });

  it("defaults to the Overview tab on the bare run URL", async () => {
    open();
    await screen.findByRole("heading", { name: "Sample Shop" });
    // data-testid is on the tab's <a> (react-bootstrap's Nav.Link) itself.
    const overviewTab = await screen.findByTestId("model-tab-overview");
    expect(overviewTab.className).toContain("active");
  });

  it("falls back to Overview for an unknown tab slug", async () => {
    open("/applications/APP-1/runs/RUN-1/not-a-real-tab");
    const overviewTab = await screen.findByTestId("model-tab-overview");
    expect(overviewTab.className).toContain("active");
  });

  it("opens the Threats tab directly from the URL", async () => {
    open("/applications/APP-1/runs/RUN-1/threats");
    const threatsTab = await screen.findByTestId("model-tab-threats");
    expect(threatsTab.className).toContain("active");
    expect(await screen.findByText("Spoofing of Web")).toBeInTheDocument();
  });

  it("switching tabs updates the URL and the active tab", async () => {
    open();
    await screen.findByRole("heading", { name: "Sample Shop" });

    const findingsTab = await screen.findByTestId("model-tab-findings");
    fireEvent.click(findingsTab);

    await waitFor(() => {
      expect(findingsTab.className).toContain("active");
    });
    expect(await screen.findByText(/No findings for this run/)).toBeInTheDocument();
  });

  it("a stat tile switches to the tab that explains it", async () => {
    open();
    const findingsStat = await screen.findByTestId("model-stat-findings");
    fireEvent.click(findingsStat);

    const findingsTab = await screen.findByTestId("model-tab-findings");
    await waitFor(() => {
      expect(findingsTab.className).toContain("active");
    });
  });

  it("'View all threats for this element' switches to Threats filtered to that element", async () => {
    open();
    // The Diagram tab isn't mounted until it's the active tab.
    fireEvent.click(await screen.findByTestId("model-tab-diagram"));
    // The Diagram tab's node renders the component's short name as a label.
    const nodeLabel = await screen.findByText("Web", { selector: "span" });
    fireEvent.click(nodeLabel);

    const viewAllButton = await screen.findByRole("button", { name: "View all threats for this element" });
    fireEvent.click(viewAllButton);

    const threatsTab = await screen.findByTestId("model-tab-threats");
    await waitFor(() => {
      expect(threatsTab.className).toContain("active");
    });
    expect(await screen.findByText("Spoofing of Web")).toBeInTheDocument();
  });

  describe("a run that did not complete", () => {
    const FAILED = {
      ...RUN,
      id: "RUN-2",
      status: "failed",
      error_message: 'Could not read data source "bad.yaml": mapping values are not allowed here',
    };

    function routeFailed(url: string): unknown {
      if (url.endsWith("/runs/RUN-2")) return FAILED;
      if (/\/runs\/RUN-2\/(dfd)/.test(url)) return { nodes: [], edges: [], boundaries: [] };
      if (/\/runs\/RUN-2\/(findings|sbom)/.test(url)) return /sbom/.test(url) ? null : [];
      if (url.endsWith("/runs/RUN-2/threats"))
        return {
          ...THREATS,
          threats: [],
          summary: { total: 0, by_status: {}, open_by_severity: {}, open_by_risk: {} },
        };
      if (url.endsWith("/api/applications/APP-1/runs"))
        return [
          { id: "RUN-1", status: "completed", started_at: "2026-09-20T10:00:00Z" },
          { id: "RUN-2", status: "failed", started_at: "2026-09-21T10:00:00Z" },
        ];
      return routeFor(url);
    }

    beforeEach(() => {
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input.toString();
        return Promise.resolve(json(routeFailed(url)));
      });
    });

    it("explains the failure and offers the way forward", async () => {
      open("/applications/APP-1/runs/RUN-2");
      const page = await screen.findByTestId("failed-run");
      expect(page).toHaveTextContent("This run could not finish.");
      expect(page).toHaveTextContent('Could not read data source "bad.yaml"');
      expect(screen.getByRole("link", { name: "Back to Threat models" })).toHaveAttribute("href", "/applications");
      expect(await screen.findByRole("link", { name: "Back to the last completed run" })).toHaveAttribute(
        "href",
        "/applications/APP-1/runs/RUN-1",
      );
      expect(screen.getByRole("button", { name: "Run again" })).toBeInTheDocument();
      expect(fetchMock.mock.calls.some(([u]) => /APP-1\/data-sources/.test(String(u)))).toBe(true);
    });

    it("starts a new run from the Run again button", async () => {
      open("/applications/APP-1/runs/RUN-2");
      fireEvent.click(await screen.findByRole("button", { name: "Run again" }));
      await waitFor(() =>
        expect(fetchMock).toHaveBeenCalledWith(
          "/api/applications/APP-1/runs",
          expect.objectContaining({ method: "POST" }),
        ),
      );
    });

    it("omits the last-completed link when no run ever completed", async () => {
      fetchMock.mockImplementation((input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input.toString();
        if (url.endsWith("/api/applications/APP-1/runs"))
          return Promise.resolve(json([{ id: "RUN-2", status: "failed", started_at: "2026-09-21T10:00:00Z" }]));
        return Promise.resolve(json(routeFailed(url)));
      });
      open("/applications/APP-1/runs/RUN-2");
      await screen.findByTestId("failed-run");
      await waitFor(() => expect(fetchMock.mock.calls.some(([u]) => /APP-1\/staleness/.test(String(u)))).toBe(true));
      expect(screen.queryByRole("link", { name: "Back to the last completed run" })).toBeNull();
    });
  });
});
