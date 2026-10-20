import type { ReactNode } from "react";
import type { DashboardOut } from "./pages/dashboard/types";
// Resolved by vite.config.ts and tsconfig paths: an empty stub unless a plugin frontend is configured at build time.
import proExtension from "@kresheen/pro";

export interface ExtensionRoute {
  path: string;
  element: ReactNode;
}

export interface ExtensionNavItem {
  to: string;
  label: string;
  icon: string; // a Bootstrap Icons class such as "bi-grid"
  placement?: "top" | "bottom";
}

export interface ExtensionSettingsSection {
  id: string;
  render: (props: { hashId: string }) => ReactNode;
  /** Survives `applyCapabilities` when the backend reports no plugin feature: for a status card that explains why. */
  showWhenDisabled?: boolean;
}

export interface ExtensionRunTab {
  key: string;
  label: string;
  render: (props: { applicationId: string; runId: string; refreshKey: unknown }) => ReactNode;
}

export interface ExtensionDashboardPanel {
  /** Key in the dashboard's `extensions` object (the plugin name). */
  key: string;
  render: (props: { data: unknown; dashboard: DashboardOut }) => ReactNode;
}

export interface ExtensionRunHeaderAction {
  id: string;
  render: (props: { applicationId: string; runId: string }) => ReactNode;
}

/** A group as the groups page shows it to a group admin. */
export interface ExtensionGroup {
  id: string;
  name: string;
  my_role?: string | null;
}

/** A control on a group's row in the groups page, shown only to someone who administers the group. */
export interface ExtensionGroupAction {
  id: string;
  /** `onChanged` asks the page to reload its groups. */
  render: (props: { group: ExtensionGroup; onChanged: () => void }) => ReactNode;
}

export interface ExtensionLoginButton {
  id: string;
  render: () => ReactNode;
}

/** Everything a plugin frontend can add. Every slot is optional. */
export interface FrontendExtension {
  routes?: ExtensionRoute[];
  navItems?: ExtensionNavItem[];
  settingsSections?: ExtensionSettingsSection[];
  runTabs?: ExtensionRunTab[];
  dashboardPanels?: ExtensionDashboardPanel[];
  runHeaderActions?: ExtensionRunHeaderAction[];
  loginButtons?: ExtensionLoginButton[];
  groupActions?: ExtensionGroupAction[];
}

export const extensions: Required<FrontendExtension> = {
  routes: proExtension.routes ?? [],
  navItems: proExtension.navItems ?? [],
  settingsSections: proExtension.settingsSections ?? [],
  runTabs: proExtension.runTabs ?? [],
  dashboardPanels: proExtension.dashboardPanels ?? [],
  runHeaderActions: proExtension.runHeaderActions ?? [],
  loginButtons: proExtension.loginButtons ?? [],
  groupActions: proExtension.groupActions ?? [],
};

/** True when any slot has an entry, so a plugin frontend was built in. */
export function hasExtensions(): boolean {
  return Object.values(extensions).some((entries) => entries.length > 0);
}

/**
 * Hides the plugin frontend when the backend runs no plugin feature (no plugin installed, or its licence is missing,
 * invalid or expired), so the UI never shows controls whose routes do not exist. Empties every slot in place, except
 * settings sections that ask to stay (the licence status card); call it before the first render. `capabilities` is the `/api/capabilities` answer, or null when it could not be read
 * (treated as no features).
 */
export function applyCapabilities(capabilities: { features: string[] } | null): void {
  if (capabilities && capabilities.features.length > 0) return;
  const { settingsSections, ...others } = extensions;
  for (const entries of Object.values(others)) entries.length = 0;
  const kept = settingsSections.filter((section) => section.showWhenDisabled);
  settingsSections.length = 0;
  settingsSections.push(...kept);
}
