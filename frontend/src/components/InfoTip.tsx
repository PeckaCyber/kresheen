import { OverlayTrigger, Tooltip } from "react-bootstrap";
import { ReactNode } from "react";

interface InfoTipProps {
  text?: string;
  children: ReactNode;
}

export function InfoTip({ text, children }: InfoTipProps) {
  if (!text) {
    return children;
  }

  return (
    <OverlayTrigger placement="top" trigger={["hover", "focus"]} overlay={<Tooltip>{text}</Tooltip>}>
      <span tabIndex={0} role="button" style={{ cursor: "default" }}>
        {children}
      </span>
    </OverlayTrigger>
  );
}
