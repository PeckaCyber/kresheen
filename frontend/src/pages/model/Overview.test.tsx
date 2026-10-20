import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ActionPlanOut } from "../ActionPlanPanel";
import type { CompletenessOut } from "../CompletenessPanel";
import type { RunDiffOut } from "../RunDiffPanel";
import { Overview } from "./Overview";

const EMPTY_DIFF: RunDiffOut = {
  current_run_id: "RUN-1",
  previous_run_id: null,
  new_components: [],
  removed_components: [],
  new_flows: [],
  removed_flows: [],
  new_threats: [],
  resolved_threats: [],
  new_findings: [],
  resolved_findings: [],
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

const COMPLETENESS: CompletenessOut = {
  score: 40,
  answered: 2,
  total: 5,
  items: [
    {
      id: "authenticates_callers|component:1",
      check: "authenticates_callers",
      element_kind: "component",
      element_id: "N-1",
      element_name: "Portal",
      message: "Does Portal require callers to authenticate?",
      why: "Raises the likelihood of impersonation if not.",
      impact: "high",
      fix: {
        property_key: "authenticates_callers",
        kind: "bool",
        options: [],
        suggested_value: null,
        suggestion_reason: "",
        alternative: null,
      },
    },
  ],
};

const ACTION_PLAN: ActionPlanOut = {
  actions: [
    {
      id: "A-1",
      text: "Require authentication on Portal",
      score: 10,
      max_risk: "high",
      basis: "generic",
      threat_count: 3,
      element_count: 1,
      elements: ["Portal"],
      cwe_refs: [],
      threat_keys: ["T-1"],
      status: "todo",
      note: "",
    },
  ],
  summary: { total: 1, by_status: { todo: 1 }, open_threats_covered: 3 },
};

describe("Overview", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    // A fresh Response each call -- Response bodies can only be read once, and
    // this component can fire more than one fetch (the always-mounted
    // completeness disclosure, plus a PATCH when a question is answered).
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(COMPLETENESS)));
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows a first-run empty state when the model has no components", () => {
    render(
      <Overview
        applicationId="APP-1"
        runId="RUN-1"
        componentCount={0}
        completeness={null}
        actionPlan={null}
        threatsSummary={undefined}
        attackPaths={null}
        diff={null}
        onAnswered={() => {}}
        onGoToTab={() => {}}
        onCompletenessLoaded={() => {}}
      />,
    );
    expect(screen.getByText("This model has no components yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start by adding components on the Diagram tab" })).toBeInTheDocument();
  });

  it("lists the top completeness question and top action, each linking to its full tab", async () => {
    const onGoToTab = vi.fn();
    render(
      <Overview
        applicationId="APP-1"
        runId="RUN-1"
        componentCount={1}
        completeness={COMPLETENESS}
        actionPlan={ACTION_PLAN}
        threatsSummary={{ total: 3, by_status: { open: 3 }, open_by_severity: {}, open_by_risk: { high: 3 } }}
        attackPaths={[]}
        diff={EMPTY_DIFF}
        onAnswered={() => {}}
        onGoToTab={onGoToTab}
        onCompletenessLoaded={() => {}}
      />,
    );

    expect(screen.getByText("Does Portal require callers to authenticate?")).toBeInTheDocument();
    expect(screen.getByText("Require authentication on Portal")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "See the full action plan" }));
    expect(onGoToTab).toHaveBeenCalledWith("actions");
  });

  it("answers a quick Yes/No completeness question inline", async () => {
    const onAnswered = vi.fn();
    render(
      <Overview
        applicationId="APP-1"
        runId="RUN-1"
        componentCount={1}
        completeness={COMPLETENESS}
        actionPlan={ACTION_PLAN}
        threatsSummary={undefined}
        attackPaths={[]}
        diff={null}
        onAnswered={onAnswered}
        onGoToTab={() => {}}
        onCompletenessLoaded={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /^Yes: Does Portal require callers to authenticate/ }));

    await waitFor(() => expect(onAnswered).toHaveBeenCalled());
    const patchCall = fetchMock.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === "PATCH");
    expect(patchCall).toBeDefined();
    const [url, init] = patchCall!;
    expect(String(url)).toContain("/api/applications/APP-1/runs/RUN-1/element-properties");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      element_kind: "component",
      element_id: "N-1",
      properties: { authenticates_callers: true },
    });
  });

  it("breaks down open threats by risk", () => {
    render(
      <Overview
        applicationId="APP-1"
        runId="RUN-1"
        componentCount={1}
        completeness={COMPLETENESS}
        actionPlan={ACTION_PLAN}
        threatsSummary={{ total: 2, by_status: { open: 2 }, open_by_severity: {}, open_by_risk: { high: 1, low: 1 } }}
        attackPaths={[]}
        diff={null}
        onAnswered={() => {}}
        onGoToTab={() => {}}
        onCompletenessLoaded={() => {}}
      />,
    );
    expect(screen.getByRole("img", { name: "Open threats by risk" })).toBeInTheDocument();
  });
});
