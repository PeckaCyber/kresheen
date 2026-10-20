import { extensions } from "../extensions";
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { getThemePreference, setThemePreference, type ThemePreference } from "../theme";
import { CollapsibleCard } from "./CollapsibleCard";
import { Button, Form } from "react-bootstrap";
import { ApiTokensSection } from "./ApiTokensSection";
import { ChangePasswordSection } from "./ChangePasswordSection";
import { UsersSection } from "./UsersSection";
import { useAuth } from "../auth/AuthContext";
import { useCapabilities } from "../api/capabilities";
import { AiAssistSection } from "./AiAssistSection";
import { PageHeader } from "../components/PageHeader";
function AppearanceSection() {
  const [theme, setTheme] = useState<ThemePreference>(getThemePreference);
  const options: Array<{ value: ThemePreference; label: string }> = [
    { value: "light", label: "Light" },
    { value: "dark", label: "Dark" },
    { value: "system", label: "Match my system" },
  ];
  return (
    <CollapsibleCard title="Appearance" defaultOpen>
      <Form.Group controlId="theme-preference">
        <Form.Label>Theme</Form.Label>
        <div className="d-flex gap-2 flex-wrap" role="group" aria-label="Theme">
          {options.map((o) => (
            <Button
              key={o.value}
              size="sm"
              variant={theme === o.value ? "primary" : "outline-secondary"}
              aria-pressed={theme === o.value}
              onClick={() => {
                setTheme(o.value);
                setThemePreference(o.value);
              }}
            >
              {o.label}
            </Button>
          ))}
        </div>
        <Form.Text className="text-muted d-block mt-2">Saved in this browser only.</Form.Text>
      </Form.Group>
    </CollapsibleCard>
  );
}

function AuditLogSection({ defaultOpen }: { defaultOpen?: boolean } = {}) {
  return (
    <CollapsibleCard title="Audit log" id="audit" defaultOpen={defaultOpen}>
      <p className="text-muted small mb-3">
        Every change made through the dashboard or an API token, newest first. Request contents are never recorded.
      </p>
      <Link to="/audit-log" className="btn btn-outline-secondary">
        Open audit log
      </Link>
    </CollapsibleCard>
  );
}

export function SettingsPage() {
  const { role } = useAuth();
  const { capabilities, refresh } = useCapabilities();
  const { hash } = useLocation();
  const hashId = hash.replace(/^#/, "");

  // Read the hash once on load: auto-expand and scroll to the matching
  // section (e.g. a "Change password" link elsewhere pointing at
  // /settings#account). The section renders (and gets its id) whether or
  // not it starts expanded, so the element is always there to scroll to.
  useEffect(() => {
    if (!hashId) return;
    const target = document.getElementById(hashId);
    // jsdom (tests) has no scrollIntoView.
    target?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hashId]);

  return (
    <div className="pc-page-narrow">
      <PageHeader title="Settings" />
      <AppearanceSection />
      <ChangePasswordSection defaultOpen={hashId === "account"} />
      {role === "owner" && <UsersSection defaultOpen={hashId === "users"} />}
      <h2 className="text-uppercase text-muted mt-4 mb-2" style={{ fontSize: "0.72rem", letterSpacing: "0.6px" }}>
        Integrations
      </h2>
      {extensions.settingsSections.map((section) => (
        <div key={section.id}>{section.render({ hashId })}</div>
      ))}
      <ApiTokensSection />
      <AiAssistSection
        isOwner={role === "owner"}
        aiEnabled={capabilities?.ai?.enabled ?? false}
        onInstanceChanged={() => void refresh()}
      />
      {role === "owner" && <AuditLogSection defaultOpen={hashId === "audit"} />}
    </div>
  );
}
