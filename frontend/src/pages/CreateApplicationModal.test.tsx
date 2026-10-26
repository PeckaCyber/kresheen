import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreateApplicationModal } from "./CreateApplicationModal";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("CreateApplicationModal", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("creates a blank model in the chosen group, runs it and reports the ids", async () => {
    fetchMock.mockResolvedValueOnce(json({ id: "APP-1" })).mockResolvedValueOnce(json({ id: "RUN-1" }));
    const onCreated = vi.fn();
    const onHide = vi.fn();
    render(
      <CreateApplicationModal
        show
        onHide={onHide}
        groupId={null}
        groups={[{ id: "GRP-1", name: "Payments" }]}
        preset="blank"
        onCreated={onCreated}
      />,
    );

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Shop" } });
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "GRP-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create blank model" }));

    await waitFor(() => expect(onCreated).toHaveBeenCalledWith("APP-1", "RUN-1"));
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string)).toEqual({
      name: "Shop",
      description: "",
      group_id: "GRP-1",
    });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/applications/APP-1/runs");
    expect(fetchMock).toHaveBeenCalledTimes(2); // no data source was attached
    expect(onHide).toHaveBeenCalled();
  });

  it("opens with the preset's input type selected", () => {
    render(
      <CreateApplicationModal show onHide={() => {}} groupId="GRP-1" preset="github_repository" onCreated={() => {}} />,
    );

    expect(screen.getByPlaceholderText("https://github.com/owner/repo")).toBeInTheDocument();
    expect(screen.queryByLabelText("Group")).not.toBeInTheDocument(); // no group list given: fixed group
  });

  it("shows an error and does not navigate when creation fails", async () => {
    fetchMock.mockResolvedValueOnce(json({ detail: "Unknown group" }, 422));
    const onCreated = vi.fn();
    render(<CreateApplicationModal show onHide={() => {}} groupId={null} onCreated={onCreated} />);

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Shop" } });
    fireEvent.click(screen.getByRole("button", { name: "Create blank model" }));

    expect(await screen.findByText(/Failed to create the threat model/)).toBeInTheDocument();
    expect(onCreated).not.toHaveBeenCalled();
  });
});
