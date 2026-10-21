import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GroupsPage } from "./Groups";
import { Onboarding } from "./Onboarding";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const emptyRollup = { application_count: 0, worst_severity: null, finding_count: 0, stale_count: 0 };

describe("Onboarding", () => {
  it("offers only inputs the engine reads, and says documents are not analysed", () => {
    render(<Onboarding onPick={() => {}} onDescribe={() => {}} onSample={() => {}} sampleBusy={null} sampleError={null} />);

    expect(screen.getByText("Upload infrastructure files")).toBeInTheDocument();
    expect(screen.getByText("Connect a GitHub repository")).toBeInTheDocument();
    expect(screen.getByText("Import a diagram")).toBeInTheDocument();
    expect(screen.getByText("Draw it yourself")).toBeInTheDocument();
    expect(screen.queryByText(/documentation$/i)).not.toBeInTheDocument();
    expect(screen.getByText(/does not read it yet/)).toBeInTheDocument();
  });

  it("reports which entry was picked, and the sample request", () => {
    const onPick = vi.fn();
    const onSample = vi.fn();
    const onDescribe = vi.fn();
    render(<Onboarding onPick={onPick} onDescribe={onDescribe} onSample={onSample} sampleBusy={null} sampleError={null} />);

    fireEvent.click(screen.getByRole("button", { name: /Start drawing/ }));
    expect(onPick).toHaveBeenCalledWith("blank");
    fireEvent.click(screen.getByRole("button", { name: /Choose: Connect a GitHub repository/ }));
    expect(onPick).toHaveBeenCalledWith("github_repository");
    fireEvent.click(screen.getByRole("button", { name: "Open sample: Kubernetes app" }));
    expect(onSample).toHaveBeenCalledWith("kubernetes");
    fireEvent.click(screen.getByRole("button", { name: "Open sample: AWS app" }));
    expect(onSample).toHaveBeenCalledWith("aws");
    fireEvent.click(screen.getByRole("button", { name: "Open sample: Online shop" }));
    expect(onSample).toHaveBeenCalledWith("online_shop");
    fireEvent.click(screen.getByRole("button", { name: "Describe your system" }));
    expect(onDescribe).toHaveBeenCalled();
  });

  it("shows a sample error and disables every sample while one is being created", () => {
    render(<Onboarding onPick={() => {}} onDescribe={() => {}} onSample={() => {}} sampleBusy="aws" sampleError="Nope" />);
    expect(screen.getByText("Nope")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Creating the sample.*AWS app/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Open sample: Kubernetes app" })).toBeDisabled();
  });
});

describe("GroupsPage first run", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  function setupMocks(applicationCount: number) {
    const applications = Array.from({ length: applicationCount }, (_, i) => ({
      id: `app-${i}`,
      name: `App ${i}`,
      group_id: null,
      group_name: null,
      latest_run_id: null,
      worst_severity: null,
      worst_threat_risk: null,
      finding_count: 0,
      open_threat_count: 0,
      not_analysed: false,
      stale: false,
      days_since_run: null,
      addressed_count: 0,
      total_threat_count: 0,
      completeness_score: null,
      reviewed_at: null,
      open_by_risk: {},
      open_by_category: {},
      open_action_count: null,
    }));
    const dashboardResponse = json({ applications });
    const groupsResponse = json({
      groups: [],
      ungrouped: { ...emptyRollup, application_count: applicationCount },
      overall: { ...emptyRollup, application_count: applicationCount },
    });
    fetchMock.mockResolvedValueOnce(dashboardResponse).mockResolvedValueOnce(groupsResponse);
  }

  it("shows the onboarding cards when there are no applications, and a New threat model button", async () => {
    setupMocks(0);
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Create your first threat model")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New threat model" })).toBeInTheDocument();
  });

  it("hides the onboarding once an application exists but keeps the button", async () => {
    setupMocks(2);
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByRole("button", { name: "New threat model" })).toBeInTheDocument());
    expect(screen.queryByText("Create your first threat model")).not.toBeInTheDocument();
  });

  it("opens the create dialog ready for the picked input", async () => {
    setupMocks(0);
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: /Start drawing/ }));

    expect(await screen.findByText("Draw a new threat model")).toBeInTheDocument();
    expect(screen.getByLabelText("Group")).toBeInTheDocument();
  });

  it("asks the server for the picked sample and opens its run", async () => {
    setupMocks(0);
    fetchMock.mockResolvedValueOnce(json({ application_id: "app-k", run_id: "run-k" }));
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Open sample: Kubernetes app" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    const [url, init] = fetchMock.mock.calls[2];
    expect(url).toBe("/api/applications/sample");
    expect(JSON.parse(init.body)).toEqual({ sample: "kubernetes" });
  });

  it("offers the samples from the New threat model menu once models exist", async () => {
    setupMocks(2);
    render(
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "New threat model" }));

    expect(await screen.findByText("Sample: AWS app")).toBeInTheDocument();
    expect(screen.getByText("Sample: Kubernetes app")).toBeInTheDocument();
    expect(screen.getByText("Sample: Online shop")).toBeInTheDocument();
  });
});
