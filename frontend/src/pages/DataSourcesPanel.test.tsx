import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DataSourcesPanel } from "./DataSourcesPanel";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("DataSourcesPanel", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("lists the application's current data sources", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        {
          id: "DS-1",
          type: "github_repository",
          connection_details: { repo_url: "https://github.com/acme/widget" },
          created_at: "2026-09-20T10:00:00Z",
        },
      ]),
    );

    render(<DataSourcesPanel applicationId="APP-1" />);

    expect(await screen.findByText("https://github.com/acme/widget")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText("GitHub repository")).toBeInTheDocument();
  });

  it("shows only that a token is saved and replaces or removes it without ever showing the value", async () => {
    const source = {
      id: "DS-1",
      type: "github_repository",
      connection_details: { repo_url: "https://github.com/acme/widget" },
      created_at: "2026-09-20T10:00:00Z",
      has_token: true,
      token_hint: "1234",
    };
    fetchMock
      .mockResolvedValueOnce(jsonResponse([source])) // initial load
      .mockResolvedValueOnce(jsonResponse(source)) // PUT
      .mockResolvedValueOnce(jsonResponse([{ ...source, token_hint: "9999" }])) // reload
      .mockResolvedValueOnce(jsonResponse({ ...source, has_token: false })) // DELETE
      .mockResolvedValueOnce(jsonResponse([{ ...source, has_token: false, token_hint: null }])); // reload

    render(<DataSourcesPanel applicationId="APP-1" />);

    expect(await screen.findByText("Token saved (ends in 1234)")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Replace" }));
    fireEvent.change(screen.getByLabelText("New GitHub token"), { target: { value: "ghp_new9999" } });
    fireEvent.click(screen.getByRole("button", { name: "Save token" }));
    expect(await screen.findByText("Token saved (ends in 9999)")).toBeInTheDocument();
    expect(fetchMock.mock.calls[1][0]).toBe("/api/applications/APP-1/data-sources/DS-1/token");
    expect(fetchMock.mock.calls[1][1].method).toBe("PUT");

    fireEvent.click(screen.getByRole("button", { name: "Remove token" }));
    expect(await screen.findByText("No token")).toBeInTheDocument();
    expect(fetchMock.mock.calls[3][1].method).toBe("DELETE");
  });

  it("shows an empty state when there are no sources yet", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));

    render(<DataSourcesPanel applicationId="APP-1" />);

    expect(await screen.findByText(/No data sources yet/)).toBeInTheDocument();
  });

  it("adds a data source and reloads the list, notifying the caller", async () => {
    const onChanged = vi.fn();
    fetchMock
      .mockResolvedValueOnce(jsonResponse([])) // initial load
      .mockResolvedValueOnce(jsonResponse({ id: "DS-2", type: "github_repository" })) // POST
      .mockResolvedValueOnce(
        jsonResponse([
          { id: "DS-2", type: "github_repository", connection_details: {}, created_at: "2026-09-22T10:00:00Z" },
        ]),
      ); // reload

    render(<DataSourcesPanel applicationId="APP-1" onChanged={onChanged} />);
    await screen.findByText(/No data sources yet/);

    fireEvent.change(screen.getByRole("combobox"), { target: { value: "github_repository" } });
    fireEvent.change(screen.getByPlaceholderText("https://github.com/owner/repo"), {
      target: { value: "https://github.com/acme/widget" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add data source" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [postUrl, postInit] = fetchMock.mock.calls[1];
    expect(postUrl).toBe("/api/applications/APP-1/data-sources");
    expect(postInit.method).toBe("POST");
  });

  it("removes a data source and reloads the list, notifying the caller", async () => {
    const onChanged = vi.fn();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse([
          {
            id: "DS-1",
            type: "manifest_upload",
            connection_details: { filename: "manifest.yaml" },
            created_at: "2026-09-20T10:00:00Z",
          },
        ]),
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(jsonResponse([]));

    render(<DataSourcesPanel applicationId="APP-1" onChanged={onChanged} />);
    await screen.findByText("manifest.yaml");

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const [deleteUrl, deleteInit] = fetchMock.mock.calls[1];
    expect(deleteUrl).toBe("/api/applications/APP-1/data-sources/DS-1");
    expect(deleteInit.method).toBe("DELETE");
  });
  it("flags an analysed source whose vulnerability scan did not run, instead of showing it as clean", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        {
          id: "DS-1",
          type: "github_repository",
          connection_details: { repo_url: "https://github.com/acme/widget" },
          created_at: "2026-09-20T10:00:00Z",
        },
      ]),
    );

    render(
      <DataSourcesPanel
        applicationId="APP-1"
        sourceResults={[
          {
            data_source_id: "DS-1",
            type: "github_repository",
            status: "analysed",
            component_count: 3,
            vulnerability_count: 0,
            message: "",
            warnings: ["The vulnerability scan timed out, so dependencies were not checked for known vulnerabilities."],
          },
        ]}
      />,
    );

    const warning = await screen.findByTestId("source-warning");
    expect(warning).toHaveTextContent("Incomplete");
    expect(warning).toHaveTextContent("scan timed out");
  });

  it("shows no warning for a fully analysed source", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        {
          id: "DS-1",
          type: "manifest_upload",
          connection_details: { filename: "m.yaml" },
          created_at: "2026-09-20T10:00:00Z",
        },
      ]),
    );
    render(
      <DataSourcesPanel
        applicationId="APP-1"
        sourceResults={[
          {
            data_source_id: "DS-1",
            type: "manifest_upload",
            status: "analysed",
            component_count: 2,
            vulnerability_count: 0,
            message: "",
          },
        ]}
      />,
    );
    await screen.findByRole("table");
    expect(screen.queryByTestId("source-warning")).toBeNull();
  });
});
