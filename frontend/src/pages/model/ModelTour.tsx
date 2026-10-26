import { useEffect, useState } from "react";
import { Card, Button } from "react-bootstrap";
import { type ModelTabKey } from "./ModelTabs";

export interface ModelTourProps {
  onGoToTab: (tab: ModelTabKey) => void;
}

interface TourStep {
  title: string;
  content: string;
  tabKey: ModelTabKey;
}

const TOUR_STEPS: TourStep[] = [
  {
    title: "Overview",
    content:
      "Start here. It shows the few things worth doing next: questions that sharpen your threats, and the fixes that matter most.",
    tabKey: "overview",
  },
  {
    title: "Diagram",
    content: "Your system as boxes and arrows. Click any box to see its threats and state what you know about it.",
    tabKey: "diagram",
  },
  {
    title: "Threats",
    content:
      "Every threat the rules found, riskiest first. Mark each one mitigated, accepted or not applicable as you go.",
    tabKey: "threats",
  },
  {
    title: "Action plan",
    content: "The same threats turned into a ranked to-do list of fixes you can hand to a team.",
    tabKey: "actions",
  },
];

export function ModelTour({ onGoToTab }: ModelTourProps) {
  const [visible, setVisible] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    try {
      const isDone = localStorage.getItem("kresheen-tour-done") === "1";
      setVisible(!isDone);
    } catch {
      // localStorage may be unavailable; don't show the tour
      setVisible(false);
    }
  }, []);

  const handleDone = () => {
    try {
      localStorage.setItem("kresheen-tour-done", "1");
    } catch {
      // localStorage may be unavailable; ignore
    }
    setVisible(false);
  };

  const handleSkip = () => {
    try {
      localStorage.setItem("kresheen-tour-done", "1");
    } catch {
      // localStorage may be unavailable; ignore
    }
    setVisible(false);
  };

  const handleNext = () => {
    if (currentStep < TOUR_STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleGoToTab = () => {
    onGoToTab(TOUR_STEPS[currentStep].tabKey);
  };

  if (!visible) {
    return null;
  }

  const step = TOUR_STEPS[currentStep];
  const isLastStep = currentStep === TOUR_STEPS.length - 1;

  return (
    <Card
      role="dialog"
      aria-label="Quick tour"
      style={{
        position: "fixed",
        right: 24,
        bottom: 24,
        maxWidth: 360,
        zIndex: 1050,
        boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
      }}
      className="bg-body border-secondary"
    >
      <Card.Body className="p-3">
        <div className="mb-2">
          <Card.Title className="mb-2">{step.title}</Card.Title>
          <p className="small mb-3 text-body-secondary">{step.content}</p>
        </div>

        <div className="d-flex gap-2 mb-3">
          <Button size="sm" variant="primary" onClick={handleGoToTab} className="flex-grow-1">
            Go to {step.title}
          </Button>
        </div>

        <div className="d-flex justify-content-between align-items-center">
          <small className="text-muted">
            {currentStep + 1} of {TOUR_STEPS.length}
          </small>
          <div className="d-flex gap-2">
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={handleBack}
              disabled={currentStep === 0}
              className="btn-sm"
            >
              Back
            </Button>
            {!isLastStep ? (
              <Button size="sm" variant="outline-secondary" onClick={handleNext} className="btn-sm">
                Next
              </Button>
            ) : (
              <Button size="sm" variant="outline-secondary" onClick={handleDone} className="btn-sm">
                Done
              </Button>
            )}
          </div>
        </div>

        <div className="text-center mt-2">
          <Button variant="link" size="sm" className="text-decoration-none text-muted p-0" onClick={handleSkip}>
            Skip tour
          </Button>
        </div>
      </Card.Body>
    </Card>
  );
}
