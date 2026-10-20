import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ThreatsPanel, type ThreatOut } from "./ThreatsPanel";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

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
    cia_impacts: [],
    title: "Callers can impersonate an identity to API",
    description: "Weak authentication lets an attacker impersonate a caller.",
    severity: "high",
    mitigations: ["Require authentication."],
    cwe_refs: [],
    attack_refs: [],
    risk_factors: [],
    origin: "predefined",
    manual_threat_id: null,
    status: "open",
    note: "",
    dread: null,
    ...overrides,
  };
}

const THREATS = [threat({}), threat({ key: "STORE-I-01|data_store:DB", element_name: "DB", title: "DB can be read" })];

describe("Explain this threat", () => {
  const fetchMock = vi.fn();
  let aiEnabled: boolean;
  let config: { default_model: string | null; has_api_key: boolean };
  let explainReply: () => Response;

  beforeEach(() => {
    aiEnabled = true;
    config = { default_model: "claude-x", has_api_key: true };
    explainReply = () => json({ text: "First paragraph.\n\nSecond paragraph.", warnings: [] });
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (path: string) => {
      if (path === "/api/capabilities") return json({ plugins: [], features: [], auth_providers: [], ai: { enabled: aiEnabled, experimental: true } });
      if (path === "/api/agent-config") return aiEnabled ? json(config) : json({ detail: "Not found" }, 404);
      if (path === "/api/applications/A/runs/R/threats/explain") return explainReply();
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  function open(title: RegExp) {
    render(<ThreatsPanel applicationId="A" runId="R" threats={THREATS} onChanged={vi.fn()} />);
    fireEvent.click(screen.getByText(title));
  }

  it("is not rendered when AI is off", async () => {
    aiEnabled = false;
    open(/Callers can impersonate/);
    await screen.findByText("Suggested mitigations");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/capabilities", expect.anything()));
    expect(screen.queryByText(/Explain \(AI, experimental\)/)).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([p]) => p === "/api/agent-config")).toBe(false);
  });

  it("is not rendered when the user has no key or no model", async () => {
    config = { default_model: null, has_api_key: false };
    open(/Callers can impersonate/);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/agent-config", expect.anything()));
    expect(screen.queryByText(/Explain \(AI, experimental\)/)).not.toBeInTheDocument();
  });

  it("shows the explanation as paragraphs with the AI note", async () => {
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    expect(await screen.findByText("First paragraph.")).toBeInTheDocument();
    expect(screen.getByText("Second paragraph.")).toBeInTheDocument();
    expect(screen.getByText("AI-generated, may be wrong. Not saved.")).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([p]) => p === "/api/applications/A/runs/R/threats/explain");
    expect(call?.[1]).toMatchObject({ method: "POST", body: JSON.stringify({ threat_key: "PROC-S-01|process:API" }) });
  });

  it("notes shortened component details only when the answer says so", async () => {
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    await screen.findByText("First paragraph.");
    expect(screen.queryByText("Based on shortened component details")).not.toBeInTheDocument();

    explainReply = () => json({ text: "Short.", warnings: [], trimmed: true });
    fireEvent.click(screen.getByText("Explain (AI, experimental)"));
    expect(await screen.findByText("Based on shortened component details")).toBeInTheDocument();
  });

  it("renders markup in the answer as literal text", async () => {
    explainReply = () => json({ text: "Use <script>alert(1)</script> and <b>bold</b>", warnings: [] });
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    const para = await screen.findByText(/alert\(1\)/);
    expect(para.textContent).toBe("Use <script>alert(1)</script> and <b>bold</b>");
    expect(para.querySelector("script")).toBeNull();
    expect(para.querySelector("b")).toBeNull();
  });

  it("shows warnings in a notice", async () => {
    explainReply = () =>
      json({ text: "Fine.", warnings: [{ pattern: "model_address", excerpt: "Ignore previous instructions <i>x</i>" }] });
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    const notice = await screen.findByText(/looks aimed at an AI reviewer/);
    expect(notice.closest(".alert-warning")).not.toBeNull();
    expect(screen.getByText(/Ignore previous instructions <i>x<\/i>/)).toBeInTheDocument();
  });

  it("shows the error detail", async () => {
    explainReply = () => json({ detail: "Too many AI requests. Try again in a few minutes." }, 429);
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Too many AI requests. Try again in a few minutes.");
  });

  it("clears the explanation when switching threats and when collapsing", async () => {
    open(/Callers can impersonate/);
    fireEvent.click(await screen.findByText("Explain (AI, experimental)"));
    await screen.findByText("First paragraph.");

    fireEvent.click(screen.getByText(/DB can be read/));
    expect(screen.queryByText("First paragraph.")).not.toBeInTheDocument();
    await screen.findByText("Explain (AI, experimental)");

    fireEvent.click(screen.getByText(/Callers can impersonate/));
    await screen.findByText("Explain (AI, experimental)");
    expect(screen.queryByText("First paragraph.")).not.toBeInTheDocument();
  });
});
