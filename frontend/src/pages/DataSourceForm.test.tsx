import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { combineManifestFiles, DataSourceDraftFields, newDraft } from "./DataSourceForm";

// jsdom's File may lack .text(); the form only needs the string, so give test files one.
function file(name: string, content: string): File {
  const f = new File([content], name);
  Object.defineProperty(f, "text", { value: () => Promise.resolve(content) });
  return f;
}

describe("combineManifestFiles", () => {
  it("passes a single file (a Terraform plan or one YAML) through unchanged", async () => {
    expect(await combineManifestFiles([file("plan.json", '{"a":1}')])).toEqual({
      fileName: "plan.json",
      content: '{"a":1}',
    });
  });

  it("joins several YAML files into one manifest with document separators", async () => {
    const result = await combineManifestFiles([
      file("a.yaml", "kind: A"),
      file("b.yml", "kind: B\n"),
      file("c.YAML", "kind: C"),
    ]);

    expect(result).toEqual({
      fileName: "3 files: a.yaml, b.yml, c.YAML",
      content: "kind: A\n---\nkind: B\n---\nkind: C\n",
    });
  });

  it("names the first three files and elides the rest", async () => {
    const files = ["a", "b", "c", "d", "e"].map((n) => file(`${n}.yaml`, "kind: X"));
    expect(await combineManifestFiles(files)).toMatchObject({ fileName: "5 files: a.yaml, b.yaml, c.yaml, ..." });
  });

  it("refuses to mix a JSON plan with other files and says which ones", async () => {
    const result = await combineManifestFiles([file("a.yaml", "kind: A"), file("plan.json", "{}")]);
    expect(result).toEqual({ error: expect.stringContaining("Not YAML: plan.json") });
  });
});

describe("DataSourceDraftFields file input", () => {
  it("accepts several files for a manifest but one for a diagram", () => {
    const { rerender } = render(<DataSourceDraftFields draft={newDraft()} onChange={() => {}} />);
    expect(screen.getByLabelText(/Manifest files/)).toHaveAttribute("multiple");

    rerender(<DataSourceDraftFields draft={{ ...newDraft(), type: "architecture_diagram" }} onChange={() => {}} />);
    const diagram = screen.getByLabelText(/Threat Dragon JSON, draw.io, Mermaid or Threagile YAML/);
    expect(diagram).not.toHaveAttribute("multiple");
    expect(diagram.getAttribute("accept")).toContain(".drawio");
  });

  it("reports the combined manifest, and a warning when the selection cannot be combined", async () => {
    const onChange = vi.fn();
    render(<DataSourceDraftFields draft={newDraft()} onChange={onChange} />);
    const input = screen.getByLabelText(/Manifest files/);

    fireEvent.change(input, { target: { files: [file("a.yaml", "kind: A"), file("b.yaml", "kind: B")] } });
    await waitFor(() =>
      expect(onChange).toHaveBeenCalledWith({
        fileName: "2 files: a.yaml, b.yaml",
        content: "kind: A\n---\nkind: B\n",
      }),
    );

    fireEvent.change(input, { target: { files: [file("a.yaml", "kind: A"), file("p.json", "{}")] } });
    expect(await screen.findByText(/Select several Kubernetes YAML files/)).toBeInTheDocument();
    expect(onChange).toHaveBeenLastCalledWith({ fileName: "", content: "" });
  });
});
