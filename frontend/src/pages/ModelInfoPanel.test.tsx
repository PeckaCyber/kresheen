import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ModelInfoPanel } from "./ModelInfoPanel";
import { offerDemoMethodology } from "../testMethodologies";
import { setAvailableMethodologies } from "../methodology";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const METADATA = {
  name: "Shop",
  description: "The online shop",
  owner: "Jane Owner",
  reviewer: "",
  contributors: ["Alex", "Sam"],
  methodologies: ["STRIDE"],
};

describe("ModelInfoPanel", () => {
  offerDemoMethodology();
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("shows the current metadata, with 'Not set' for empty fields", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(METADATA));

    render(<ModelInfoPanel applicationId="APP-1" />);

    expect(await screen.findByText("Jane Owner")).toBeInTheDocument();
    expect(screen.getByText("Alex, Sam")).toBeInTheDocument();
    expect(screen.getByText("Not set")).toBeInTheDocument(); // reviewer is empty
  });

  it("edits and saves metadata, sending a PATCH with parsed contributors", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(METADATA))
      .mockResolvedValueOnce(jsonResponse({ ...METADATA, reviewer: "Pat Reviewer", contributors: ["Alex"] }));

    render(<ModelInfoPanel applicationId="APP-1" />);
    await screen.findByText("Jane Owner");

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const contributorsField = screen.getByLabelText("Contributors (comma-separated)");
    fireEvent.change(contributorsField, { target: { value: "Alex" } });
    fireEvent.change(screen.getByLabelText("Reviewer"), { target: { value: "Pat Reviewer" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(screen.getByText("Pat Reviewer")).toBeInTheDocument());
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/applications/APP-1/metadata");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body)).toEqual({
      name: "Shop",
      description: "The online shop",
      owner: "Jane Owner",
      reviewer: "Pat Reviewer",
      contributors: ["Alex"],
      methodologies: ["STRIDE"],
    });
  });

  it("toggles a methodology on and sends it in the PATCH", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(METADATA))
      .mockResolvedValueOnce(jsonResponse({ ...METADATA, methodologies: ["STRIDE", "Demo"] }));

    render(<ModelInfoPanel applicationId="APP-1" />);
    await screen.findByText("Jane Owner");

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Demo" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(screen.getByText("STRIDE, Demo")).toBeInTheDocument());
    const [, init] = fetchMock.mock.calls[1];
    expect(JSON.parse(init.body).methodologies).toEqual(["STRIDE", "Demo"]);
  });

  it("cancels without saving", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(METADATA));

    render(<ModelInfoPanel applicationId="APP-1" />);
    await screen.findByText("Jane Owner");

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.getByText("Jane Owner")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("offers only STRIDE when the installation offers no other methodology", async () => {
    setAvailableMethodologies(null);
    fetchMock.mockResolvedValueOnce(jsonResponse(METADATA));

    render(<ModelInfoPanel applicationId="APP-1" />);
    await screen.findByText("Jane Owner");
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));

    expect(screen.getAllByRole("checkbox").map((c) => c.getAttribute("id"))).toEqual(["model-info-methodology-STRIDE"]);
  });

  it("says so when the saved selection includes a methodology that is not available", async () => {
    setAvailableMethodologies(null);
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...METADATA, methodologies: ["STRIDE", "Demo"] }));

    render(<ModelInfoPanel applicationId="APP-1" />);
    await screen.findByText("Jane Owner");

    expect(screen.getByRole("note")).toHaveTextContent("Demo is not available in this installation");

    // The stale entry stays visible and ticked while editing, and is dropped only if the user unticks it.
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.getByRole("checkbox", { name: "Demo (not available)" })).toBeChecked();
  });
});
