import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ActionPlanPanel, type ActionOut, type ActionPlanOut } from "./ActionPlanPanel";

function action(overrides: Partial<ActionOut>): ActionOut {
  return {
    id: "ACT-1",
    text: "Add a default-deny NetworkPolicy.",
    score: 30,
    max_risk: "high",
    basis: "observed",
    threat_count: 3,
    element_count: 2,
    elements: ["quay-app", "redis"],
    cwe_refs: ["CWE-923"],
    threat_keys: ["a", "b", "c"],
    status: "todo",
    note: "",
    ...overrides,
  };
}

function plan(actions: ActionOut[]): ActionPlanOut {
  const open = actions.filter((a) => a.status === "todo" || a.status === "in_progress");
  return {
    actions,
    summary: { total: actions.length, by_status: {}, open_threats_covered: open.reduce((n, a) => n + a.threat_count, 0) },
  };
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("ActionPlanPanel", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("lists open actions ranked, with what each covers, and offers the CSV", async () => {
    fetchMock.mockResolvedValue(json(plan([action({}), action({ id: "ACT-2", text: "Rotate credentials.", threat_count: 1 })])));
    render(<ActionPlanPanel applicationId="A" runId="R" />);

    expect(await screen.findByText("Add a default-deny NetworkPolicy.")).toBeInTheDocument();
    expect(screen.getByText("3 threats on 2 elements")).toBeInTheDocument();
    expect(screen.getByText((_, el) => el?.tagName === "SPAN" && (el.textContent ?? "").startsWith("2 open actions covering 4 open threats"))).toBeInTheDocument();
    expect(screen.getByText("Download checklist (CSV)")).toHaveAttribute("href", "/api/applications/A/runs/R/action-plan.csv");
  });

  it("shows only the top 10 until asked for all", async () => {
    const many = Array.from({ length: 12 }, (_, i) => action({ id: `ACT-${i}`, text: `Fix number ${i}` }));
    fetchMock.mockResolvedValue(json(plan(many)));
    render(<ActionPlanPanel applicationId="A" runId="R" />);

    await screen.findByText("Fix number 0");
    expect(screen.queryByText("Fix number 11")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Show all 12 open actions"));
    expect(screen.getByText("Fix number 11")).toBeInTheDocument();
  });

  it("saves a status change and reports the refreshed plan", async () => {
    const onLoaded = vi.fn();
    fetchMock
      .mockResolvedValueOnce(json(plan([action({})])))
      .mockResolvedValueOnce(json(plan([action({ status: "in_progress" })])));
    render(<ActionPlanPanel applicationId="A" runId="R" onLoaded={onLoaded} />);

    fireEvent.change(await screen.findByLabelText(/Status of/), { target: { value: "in_progress" } });

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/applications/A/runs/R/action-plan/ACT-1/status");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ status: "in_progress", note: "" });
    await waitFor(() => expect(onLoaded).toHaveBeenLastCalledWith(expect.objectContaining({ actions: [expect.objectContaining({ status: "in_progress" })] })));
  });

  it("asks for a reason before declining a fix, and will not save without one", async () => {
    fetchMock
      .mockResolvedValueOnce(json(plan([action({})])))
      .mockResolvedValueOnce(json(plan([action({ status: "wont_do", note: "Not our data" })])));
    render(<ActionPlanPanel applicationId="A" runId="R" />);

    fireEvent.change(await screen.findByLabelText(/Status of/), { target: { value: "wont_do" } });
    expect(fetchMock).toHaveBeenCalledTimes(1); // nothing sent yet
    const save = screen.getByText("Save");
    expect(save).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Reason for declining this fix"), { target: { value: "Not our data" } });
    fireEvent.click(save);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(JSON.parse((fetchMock.mock.calls[1][1] as RequestInit).body as string)).toEqual({ status: "wont_do", note: "Not our data" });
  });

  it("tucks done and declined actions away and says so when nothing is open", async () => {
    fetchMock.mockResolvedValue(json(plan([action({ status: "done" })])));
    render(<ActionPlanPanel applicationId="A" runId="R" />);

    expect(await screen.findByText(/No open actions/)).toBeInTheDocument();
    expect(screen.queryByText("Add a default-deny NetworkPolicy.")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(/Show 1 done or declined/));
    expect(screen.getByText("Add a default-deny NetworkPolicy.")).toBeInTheDocument();
  });

  it("shows how to verify and an example fix when an action's coverage is expanded", async () => {
    fetchMock.mockResolvedValue(
      json(plan([action({ verification: ["kubectl get networkpolicy -n <ns> lists the policy."], fix_examples: ["kind: NetworkPolicy"] })])),
    );
    render(<ActionPlanPanel applicationId="A" runId="R" />);

    fireEvent.click(await screen.findByText("3 threats on 2 elements"));

    expect(screen.getByText("How to verify it worked")).toBeInTheDocument();
    expect(screen.getByText("kubectl get networkpolicy -n <ns> lists the policy.")).toBeInTheDocument();
    expect(screen.getByLabelText("Example fix")).toHaveTextContent("kind: NetworkPolicy");
  });
});
