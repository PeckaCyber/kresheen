import { ReactNode, HTMLAttributes } from "react";
import { severityColor, severityTextColor } from "../severity";

export function RiskBadge({
  level,
  children,
  className,
  style,
  ...props
}: {
  level: string;
  children?: ReactNode;
  className?: string;
} & HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={"badge " + (className ?? "")}
      style={{
        // Callers may add sizing; the colours always come from the palette.
        ...style,
        background: severityColor(level),
        color: severityTextColor(level),
      }}
      {...props}
    >
      {children ?? level}
    </span>
  );
}
