// Per-source ingestion outcome reported by the backend (engine/source_status.py).
// A source the engine could not analyse must never look like "no threats found".
export interface SourceResult {
  data_source_id: string;
  type: string;
  status: "analysed" | "reference_only" | "empty";
  component_count: number;
  vulnerability_count: number;
  message: string;
  // Set when part of the source was read but a step did not run (e.g. the vulnerability scan).
  warnings?: string[];
}

export const SOURCE_TYPE_LABELS: Record<string, string> = {
  manifest_upload: "Manifest upload",
  github_repository: "GitHub repository",
  architecture_diagram: "Architecture diagram",
  documentation: "Documentation",
};

export const SOURCE_STATUS_LABELS: Record<SourceResult["status"], string> = {
  analysed: "Analysed",
  reference_only: "Stored, not analysed",
  empty: "No components found",
};

export function unanalysedSources(results: SourceResult[] | undefined): SourceResult[] {
  return (results ?? []).filter((result) => result.status !== "analysed");
}

// Inputs that were read but where a step did not run: the result is incomplete, never a clean one.
export function partlyAnalysedSources(results: SourceResult[] | undefined): SourceResult[] {
  return (results ?? []).filter((result) => (result.warnings?.length ?? 0) > 0);
}
