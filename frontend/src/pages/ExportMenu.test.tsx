import { fireEvent, render, screen } from "@testing-library/react";
import { createRef } from "react";
import { describe, expect, it } from "vitest";
import { ExportMenu } from "./ExportMenu";

describe("ExportMenu", () => {
  function open() {
    render(<ExportMenu applicationId="APP-1" runId="RUN-2" />);
    fireEvent.click(screen.getByRole("button", { name: "Export" }));
  }

  it("links every export to the run's endpoint", () => {
    open();

    const href = (name: string) => screen.getByRole("link", { name }).getAttribute("href");
    expect(href("Report (PDF)")).toBe("/api/applications/APP-1/runs/RUN-2/report.pdf");
    expect(href("Report (Word)")).toBe("/api/applications/APP-1/runs/RUN-2/report.docx");
    expect(href("Threats (CSV)")).toBe("/api/applications/APP-1/runs/RUN-2/threats.csv");
    expect(href("Findings (CSV)")).toBe("/api/applications/APP-1/runs/RUN-2/findings.csv");
    expect(href("Findings (SARIF)")).toBe("/api/applications/APP-1/runs/RUN-2/findings.sarif");
    expect(href("Diagram (SVG)")).toBe("/api/applications/APP-1/runs/RUN-2/dfd.svg?download=1");
    expect(href("Diagram (JSON)")).toBe("/api/applications/APP-1/runs/RUN-2/threatdragon.json");
  });

  it("downloads every export", () => {
    open();

    for (const name of [
      "Report (PDF)",
      "Report (Word)",
      "Threats (CSV)",
      "Findings (CSV)",
      "Findings (SARIF)",
      "Diagram (SVG)",
      "Diagram (JSON)",
    ]) {
      expect(screen.getByRole("link", { name })).toHaveAttribute("download");
    }
  });

  it("encodes ids so they can't break out of the path", () => {
    render(<ExportMenu applicationId="a/../b" runId="r?x=1" />);
    fireEvent.click(screen.getByRole("button", { name: "Export" }));

    expect(screen.getByRole("link", { name: "Report (PDF)" }).getAttribute("href")).toBe(
      "/api/applications/a%2F..%2Fb/runs/r%3Fx%3D1/report.pdf",
    );
  });

  it("renders the PNG capture action as a click handler, not a download link", () => {
    open();

    const png = screen.getByRole("button", { name: "Diagram (PNG)" });
    expect(png).not.toHaveAttribute("href", expect.stringContaining("/api/"));
    expect(png).not.toHaveClass("disabled");
  });

  it("clicking PNG capture without a diagram ref attached is a silent no-op", () => {
    open();

    // No diagramRef was passed to ExportMenu -- the handler's own guard
    // (`if (!diagramRef?.current...) return;`) must no-op rather than throw.
    expect(() => fireEvent.click(screen.getByRole("button", { name: "Diagram (PNG)" }))).not.toThrow();
  });

  it("clicking PNG capture with a ref attached does not crash even if capture itself fails", async () => {
    const ref = createRef<HTMLDivElement>();
    render(
      <div ref={ref}>
        <ExportMenu applicationId="APP-1" runId="RUN-2" diagramRef={ref} />
      </div>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Export" }));

    // jsdom has no real canvas/rendering support, so html-to-image's toPng
    // is expected to reject here -- the handler's catch must swallow it.
    fireEvent.click(screen.getByRole("button", { name: /Diagram \(PNG\)|Capturing/ }));
    await screen.findByRole("button", { name: "Diagram (PNG)" });
  });
});
