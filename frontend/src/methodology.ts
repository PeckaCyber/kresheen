// Shared by ModelInfoPanel, ThreatsPanel, AddThreatModal and ThreatKnowledgeBase.
// STRIDE is built in. Every other methodology comes from the server (`methodologies` in `GET /api/capabilities`,
// installed at start-up by `setAvailableMethodologies`), so an installation shows only what it can generate.
// "Custom" is for a user-authored threat that fits none of them; its category is free text. It is not selectable
// per application (selectableMethodologies) but is offered wherever a threat is authored or filtered
// (threatMethodologies).
export type Methodology = string;

export interface MethodologyInfo {
  name: string;
  description: string;
  categories: string[];
  category_descriptions: Record<string, string>;
}

export const STRIDE_METHODOLOGY: Methodology = "STRIDE";
export const CUSTOM_METHODOLOGY: Methodology = "Custom";

export const STRIDE_CATEGORY_LABELS: Record<string, string> = {
  Spoofing: "Spoofing",
  Tampering: "Tampering",
  Repudiation: "Repudiation",
  InformationDisclosure: "Information disclosure",
  DenialOfService: "Denial of service",
  ElevationOfPrivilege: "Elevation of privilege",
};

const STRIDE_INFO: MethodologyInfo = {
  name: STRIDE_METHODOLOGY,
  description:
    "Six ways an attacker can misuse a system: spoofing, tampering, repudiation, information disclosure, denial of service and elevation of privilege.",
  // STRIDE's categories are camelCase identifiers server-side; see STRIDE_CATEGORY_LABELS for the display text.
  categories: Object.keys(STRIDE_CATEGORY_LABELS),
  category_descriptions: {
    Spoofing: "Someone pretends to be a user or service they are not.",
    Tampering: "Data or code is modified without authorization.",
    Repudiation: "An attacker denies performing an action and cannot be proven otherwise.",
    InformationDisclosure: "Data is disclosed to people who should not have access.",
    DenialOfService: "An attacker makes a service unavailable or unusable.",
    ElevationOfPrivilege: "An attacker gains higher-level permissions than intended.",
  },
};

let available: MethodologyInfo[] = [STRIDE_INFO];

/** Installs the server's list. STRIDE is always the built-in entry; the server's other entries follow it in order. */
export function setAvailableMethodologies(list: MethodologyInfo[] | null | undefined): void {
  available = [
    STRIDE_INFO,
    ...(list ?? []).filter((m) => m.name !== STRIDE_METHODOLOGY && m.name !== CUSTOM_METHODOLOGY),
  ];
}

/** Names that can be selected for an application, STRIDE first. */
export function selectableMethodologies(): Methodology[] {
  return available.map((m) => m.name);
}

/** Names offered when authoring or filtering threats: the selectable ones, then Custom. */
export function threatMethodologies(): Methodology[] {
  return [...selectableMethodologies(), CUSTOM_METHODOLOGY];
}

/** `threatMethodologies()` plus any other name already in use (a stored threat whose methodology is no longer offered). */
export function threatMethodologiesWith(extra: Iterable<string>): Methodology[] {
  const names = threatMethodologies();
  for (const name of extra) if (!names.includes(name)) names.push(name);
  return names;
}

export function isMethodologyAvailable(methodology: string): boolean {
  return methodology === CUSTOM_METHODOLOGY || available.some((m) => m.name === methodology);
}

export function methodologyCategories(methodology: string): string[] {
  return available.find((m) => m.name === methodology)?.categories ?? [];
}

export function methodologyDescription(methodology: string): string | undefined {
  if (methodology === CUSTOM_METHODOLOGY) return "A threat you described yourself.";
  return available.find((m) => m.name === methodology)?.description;
}

export const CIA_DESCRIPTIONS: Record<string, string> = {
  Confidentiality: "Data could be seen by the wrong people.",
  Integrity: "Data or behaviour could be changed.",
  Availability: "The service could be slowed or stopped.",
};

// STRIDE's categories are camelCase identifiers server-side; every other methodology's categories are
// already human-readable strings.
export function categoryLabel(methodology: string, category: string | null | undefined): string {
  if (!category) return "—";
  if (methodology === STRIDE_METHODOLOGY) return STRIDE_CATEGORY_LABELS[category] ?? category;
  return category;
}

export function categoryDescription(methodology: string, category: string | null | undefined): string | undefined {
  if (!category) return undefined;
  return available.find((m) => m.name === methodology)?.category_descriptions[category];
}
