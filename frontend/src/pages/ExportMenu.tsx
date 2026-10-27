import { toPng } from "html-to-image";
import { type RefObject, useState } from "react";
import { Dropdown } from "react-bootstrap";

// Plain GET links: the session cookie rides along, so no fetch or CSRF header
// is needed (see dashboard/routes/api_report.py). Everything downloads. PNG is the one
// exception -- it's a client-side capture of the already-rendered diagram
// canvas (whatever layout the user currently has on screen), not a server
// re-render, so it has no backend endpoint at all.
export function ExportMenu({
  applicationId,
  runId,
  diagramRef,
}: {
  applicationId: string;
  runId: string;
  diagramRef?: RefObject<HTMLDivElement | null>;
}) {
  const base = `/api/applications/${encodeURIComponent(applicationId)}/runs/${encodeURIComponent(runId)}`;
  const [capturing, setCapturing] = useState(false);

  async function handlePngExport() {
    if (!diagramRef?.current || capturing) return;
    setCapturing(true);
    try {
      const dataUrl = await toPng(diagramRef.current, {
        backgroundColor: getComputedStyle(document.body).backgroundColor || "#ffffff",
        pixelRatio: 2,
      });
      const link = document.createElement("a");
      link.href = dataUrl;
      link.download = "diagram.png";
      link.click();
    } catch {
      // Best-effort: capture can fail on an empty canvas or a browser without
      // the needed APIs; nothing else to export client-side, so fail quietly.
    } finally {
      setCapturing(false);
    }
  }

  return (
    <Dropdown align="end">
      <Dropdown.Toggle size="sm" variant="outline-secondary" id="export-menu">
        Export
      </Dropdown.Toggle>
      <Dropdown.Menu>
        <Dropdown.Item href={`${base}/report.pdf`} download>
          Report (PDF)
        </Dropdown.Item>
        <Dropdown.Item href={`${base}/report.docx`} download>
          Report (Word)
        </Dropdown.Item>
        <Dropdown.Item href={`${base}/report.md`} download>
          Report (Markdown)
        </Dropdown.Item>
        <Dropdown.Divider />
        <Dropdown.Item href={`${base}/threats.csv`} download>
          Threats (CSV)
        </Dropdown.Item>
        <Dropdown.Item href={`${base}/findings.csv`} download>
          Findings (CSV)
        </Dropdown.Item>
        <Dropdown.Item href={`${base}/findings.sarif`} download>
          Findings (SARIF)
        </Dropdown.Item>
        <Dropdown.Divider />
        <Dropdown.Item href={`${base}/dfd.svg?download=1`} download>
          Diagram (SVG)
        </Dropdown.Item>
        <Dropdown.Item onClick={() => void handlePngExport()} disabled={capturing}>
          {capturing ? "Capturing..." : "Diagram (PNG)"}
        </Dropdown.Item>
        <Dropdown.Item href={`${base}/threatdragon.json`} download>
          Diagram (JSON)
        </Dropdown.Item>
      </Dropdown.Menu>
    </Dropdown>
  );
}
