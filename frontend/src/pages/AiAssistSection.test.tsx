import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AiAssistSection } from "./AiAssistSection";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const NOTICE_KEY = "kresheen-ai-notice-ack";

describe("AiAssistSection", () => {
  const fetchMock = vi.fn();
  let state: { enabled: boolean; forced_off: boolean };
  let config: { default_model: string | null; has_api_key: boolean; workspace_id: string | null };

  beforeEach(() => {
    localStorage.clear();
    fetchMock.mockReset();
    state = { enabled: false, forced_off: false };
    config = { default_model: null, has_api_key: false, workspace_id: null };
    fetchMock.mockImplementation(async (path: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body ? JSON.parse(init.body as string) : {};
      if (path === "/api/settings/ai") {
        if (method === "PUT") state = { ...state, enabled: body.enabled };
        return jsonResponse(state);
      }
      if (path === "/api/agent-config/models") {
        return jsonResponse([{ id: "model-a", display_name: "Model A" }]);
      }
      if (path === "/api/agent-config/key") {
        config = { ...config, default_model: null, has_api_key: false };
        return jsonResponse(config);
      }
      if (path === "/api/agent-config") {
        if (method === "PUT")
          config = { default_model: body.default_model, has_api_key: true, workspace_id: body.workspace_id };
        return jsonResponse(config);
      }
      return jsonResponse({}, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  function open() {
    fireEvent.click(screen.getByRole("button", { name: /AI assist/ }));
  }

  it("lets the owner turn AI on and off", async () => {
    const onChanged = vi.fn();
    render(<AiAssistSection isOwner aiEnabled={false} onInstanceChanged={onChanged} />);
    open();
    const toggle = await screen.findByLabelText("Turn on AI assist for this instance");
    await waitFor(() => expect(toggle).toBeEnabled());
    expect(screen.getByText("Experimental")).toBeInTheDocument();

    fireEvent.click(toggle);
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(toggle).toBeChecked();

    fireEvent.click(toggle);
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(2));
    expect(toggle).not.toBeChecked();
    const puts = fetchMock.mock.calls.filter(([, i]) => (i as RequestInit | undefined)?.method === "PUT");
    expect(puts.map(([, i]) => JSON.parse((i as RequestInit).body as string))).toEqual([
      { enabled: true },
      { enabled: false },
    ]);
  });

  it("disables the toggle and says why when the server forces AI off", async () => {
    state = { enabled: false, forced_off: true };
    render(<AiAssistSection isOwner aiEnabled={false} onInstanceChanged={vi.fn()} />);
    open();
    expect(
      await screen.findByText("Turned off by the server administrator (KRESHEEN_AI_DISABLED)"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Turn on AI assist for this instance")).toBeDisabled();
  });

  it("shows a member nothing while AI is off", () => {
    const { container } = render(<AiAssistSection isOwner={false} aiEnabled={false} onInstanceChanged={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not show a member the owner toggle when AI is on", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    await screen.findByLabelText("Your Anthropic API key");
    expect(screen.queryByLabelText("Turn on AI assist for this instance")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([p]) => p === "/api/settings/ai")).toBe(false);
  });

  it("hides the per-user section for the owner while AI is off", async () => {
    render(<AiAssistSection isOwner aiEnabled={false} onInstanceChanged={vi.fn()} />);
    open();
    await screen.findByLabelText("Turn on AI assist for this instance");
    expect(screen.queryByTestId("ai-key-section")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ai-notice")).not.toBeInTheDocument();
  });

  it("requires the notice to be acknowledged before the key field appears", async () => {
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    expect(await screen.findByText(/goes to Anthropic using your own API key/)).toBeInTheDocument();
    expect(screen.getByText("AI output can be wrong; review it.")).toBeInTheDocument();
    expect(screen.getByText("This feature is experimental.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Your Anthropic API key")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "I understand" }));
    expect(await screen.findByLabelText("Your Anthropic API key")).toBeInTheDocument();
    expect(localStorage.getItem(NOTICE_KEY)).toBe("1");
  });

  it("skips the notice once acknowledged", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    expect(await screen.findByLabelText("Your Anthropic API key")).toBeInTheDocument();
    expect(screen.queryByTestId("ai-notice")).not.toBeInTheDocument();
  });

  it("tests, picks a model and saves without echoing the key back", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    const field = (await screen.findByLabelText("Your Anthropic API key")) as HTMLInputElement;
    expect(field.type).toBe("password");
    expect(field.value).toBe("");

    fireEvent.change(field, { target: { value: "sk-ant-test-0000000000000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Test key" }));
    await screen.findByRole("option", { name: "Model A" });
    fireEvent.change(screen.getByLabelText("Model"), { target: { value: "model-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await screen.findByText(/Key saved/);
    const put = fetchMock.mock.calls.find(
      ([p, i]) => p === "/api/agent-config" && (i as RequestInit)?.method === "PUT",
    );
    expect(JSON.parse((put![1] as RequestInit).body as string)).toEqual({
      api_key: "sk-ant-test-0000000000000000",
      default_model: "model-a",
      workspace_id: null,
    });
    expect(field.value).toBe("");
    expect(screen.queryByDisplayValue("sk-ant-test-0000000000000000")).not.toBeInTheDocument();
  });

  it("sends an optional workspace ID with the key test and the save, and shows the saved one", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    fireEvent.change(await screen.findByLabelText("Your Anthropic API key"), { target: { value: "sk-ant-org-key" } });
    fireEvent.change(screen.getByLabelText("Workspace ID (optional)"), { target: { value: " wrkspc_01ab " } });
    fireEvent.click(screen.getByRole("button", { name: "Test key" }));
    await screen.findByRole("option", { name: "Model A" });
    const test = fetchMock.mock.calls.find(([p]) => p === "/api/agent-config/models");
    expect(JSON.parse((test![1] as RequestInit).body as string)).toEqual({
      api_key: "sk-ant-org-key",
      workspace_id: "wrkspc_01ab",
    });

    fireEvent.change(screen.getByLabelText("Model"), { target: { value: "model-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/Key saved/);
    const put = fetchMock.mock.calls.find(
      ([p, i]) => p === "/api/agent-config" && (i as RequestInit)?.method === "PUT",
    );
    expect(JSON.parse((put![1] as RequestInit).body as string).workspace_id).toBe("wrkspc_01ab");
    expect(screen.getByLabelText("Workspace ID (optional)")).toHaveValue("wrkspc_01ab");
  });

  it("removes the stored key", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    config = { default_model: "model-a", has_api_key: true, workspace_id: null };
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Remove my key" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Remove my key" })).not.toBeInTheDocument());
    expect(screen.getByText(/No key saved yet/)).toBeInTheDocument();
    const del = fetchMock.mock.calls.find(([p]) => p === "/api/agent-config/key");
    expect((del![1] as RequestInit).method).toBe("DELETE");
  });

  it("explains an invalid key, a missing server secret and a provider error", async () => {
    localStorage.setItem(NOTICE_KEY, "1");
    render(<AiAssistSection isOwner={false} aiEnabled onInstanceChanged={vi.fn()} />);
    open();
    const field = await screen.findByLabelText("Your Anthropic API key");
    fireEvent.change(field, { target: { value: "sk-ant-bad" } });

    fetchMock.mockImplementationOnce(async () => jsonResponse({ detail: "Invalid API key." }, 422));
    fireEvent.click(screen.getByRole("button", { name: "Test key" }));
    expect(await screen.findByText("Anthropic did not accept this key. Check it and try again.")).toBeInTheDocument();

    fetchMock.mockImplementationOnce(async () => jsonResponse({ detail: "no secret" }, 400));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/KRESHEEN_SECRET_KEY is not set/)).toBeInTheDocument();

    fetchMock.mockImplementationOnce(async () => jsonResponse({ detail: "Rate limited, try later." }, 502));
    fireEvent.click(screen.getByRole("button", { name: "Test key" }));
    expect(await screen.findByText(/Rate limited, try later\./)).toBeInTheDocument();
  });
});
