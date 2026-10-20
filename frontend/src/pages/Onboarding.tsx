import { Alert, Button, Card, Col, Row } from "react-bootstrap";
import type { CreatePreset } from "./CreateApplicationModal";

interface Entry {
  preset: CreatePreset;
  title: string;
  body: string;
}

// Every entry here is something the engine really reads today. Anything it would only store
// (documents, other diagram formats) is deliberately not offered as a way to start.
const ENTRIES: Entry[] = [
  {
    preset: "manifest_upload",
    title: "Upload infrastructure files",
    body: "A Terraform plan (JSON) or one or more Kubernetes YAML files. Components, exposure and misconfigurations are read from them.",
  },
  {
    preset: "github_repository",
    title: "Connect a GitHub repository",
    body: "Reads any Kubernetes manifests in the repo and scans its dependencies for known vulnerabilities.",
  },
  {
    preset: "architecture_diagram",
    title: "Import a diagram",
    body: "Reads components, connections and trust zones from a Threat Dragon, draw.io, Mermaid or Threagile file. Threats already listed in the file are not imported; they are worked out from the model.",
  },
  {
    preset: "blank",
    title: "Draw it yourself",
    body: "Start from a blank canvas. Add components and connections, state what you know about them, and threats appear as you go.",
  },
];

// Shown on the landing page until the first application exists.
export function Onboarding({
  onPick,
  onDescribe,
  onSample,
  sampleBusy,
  sampleError,
}: {
  onPick: (preset: CreatePreset) => void;
  onDescribe: () => void;
  onSample: () => void;
  sampleBusy: boolean;
  sampleError?: string | null;
}) {
  return (
    <section aria-labelledby="onboarding-title" className="mb-4">
      <h2 id="onboarding-title" className="h5">
        Create your first threat model
      </h2>
      <p className="text-muted">
        Get threats ranked by what to fix first. Start from an idea, or from what you already have:
      </p>
      <Card className="mb-3 border-primary">
        <Card.Body className="d-flex flex-wrap align-items-center gap-3">
          <div className="flex-grow-1">
            <Card.Title className="h6 mb-1">Describe your system</Card.Title>
            <Card.Text className="small text-muted mb-0">
              No files needed. Answer a few plain questions, or start from a template, and a starter model is drawn with
              your answers already stated.
            </Card.Text>
          </div>
          <Button onClick={onDescribe}>Describe your system</Button>
        </Card.Body>
      </Card>
      <Row xs={1} md={2} className="g-3 mb-3">
        {ENTRIES.map((entry) => (
          <Col key={entry.preset}>
            <Card className="h-100">
              <Card.Body className="d-flex flex-column">
                <Card.Title className="h6">{entry.title}</Card.Title>
                <Card.Text className="small text-muted flex-grow-1">{entry.body}</Card.Text>
                <Button variant="outline-primary" size="sm" className="align-self-start" onClick={() => onPick(entry.preset)}>
                  {entry.preset === "blank" ? "Start drawing" : "Choose"}
                  <span className="visually-hidden">: {entry.title}</span>
                </Button>
              </Card.Body>
            </Card>
          </Col>
        ))}
      </Row>
      {sampleError && <Alert variant="danger">{sampleError}</Alert>}
      <p className="small mb-1">
        Not sure yet?{" "}
        <Button variant="link" size="sm" className="p-0 align-baseline" disabled={sampleBusy} onClick={onSample}>
          {sampleBusy ? "Creating the sample..." : "Explore a sample model"}
        </Button>{" "}
        to see what the results look like. It is an ordinary model you can edit or delete.
      </p>
      <p className="small text-muted mb-0">
        You can attach documentation later, but it is stored for reference only; the engine does not read it yet.
      </p>
    </section>
  );
}
