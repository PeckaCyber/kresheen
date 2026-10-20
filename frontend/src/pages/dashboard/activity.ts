// Turns one raw audit event (method + FastAPI route template, see
// `dashboard/audit.py::AuditMiddleware`) into a plain-language sentence for
// the "Recent activity" panel. Pure and unit-tested.

import type { RecentActivityItem } from "./types";

interface Pattern {
  test: RegExp;
  describe: (appName: string) => string;
}

// Ordered most-specific first. Each maps one `"<METHOD> <route template>"`
// action string (exactly what the audit middleware records) to a sentence
// fragment appended after the actor.
const PATTERNS: Pattern[] = [
  { test: /^POST \/api\/applications\/\{application_id\}\/runs$/, describe: (name) => `ran ${name}` },
  {
    test: /^PUT \/api\/applications\/\{application_id\}\/runs\/\{run_id\}\/threats\/status$/,
    describe: (name) => `changed a threat status in ${name}`,
  },
  {
    test: /^POST \/api\/applications\/\{application_id\}\/runs\/\{run_id\}\/manual-threats$/,
    describe: (name) => `added a threat to ${name}`,
  },
  {
    test: /^POST \/api\/applications\/\{application_id\}\/data-sources$/,
    describe: (name) => `added a data source to ${name}`,
  },
  {
    test: /^DELETE \/api\/applications\/\{application_id\}\/data-sources\/\{[^/]+\}$/,
    describe: (name) => `removed a data source from ${name}`,
  },
  {
    test: /^PUT \/api\/applications\/\{application_id\}\/runs\/\{run_id\}\/threats\/status\/bulk$/,
    describe: (name) => `changed several threat statuses in ${name}`,
  },
  { test: /^POST \/api\/applications$/, describe: () => "created a threat model" },
  { test: /^POST \/api\/users$/, describe: () => "added a user" },
  { test: /^PATCH \/api\/users\/\{user_id\}$/, describe: () => "changed a user's access" },
  { test: /^(POST \/api\/auth\/change-password|auth\.change_password)$/, describe: () => "changed their password" },
  { test: /^PUT \/api\/applications\/\{application_id\}\/review$/, describe: (name) => `reviewed ${name}` },
  { test: /^PATCH \/api\/applications\/\{application_id\}\/group$/, describe: (name) => `moved ${name} to a different group` },
  { test: /^PATCH \/api\/applications\/\{application_id\}$/, describe: (name) => `renamed ${name}` },
  { test: /^DELETE \/api\/applications\/\{application_id\}$/, describe: (name) => `deleted ${name}` },
];

function parseTarget(target: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const part of target.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    fields[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return fields;
}

export function describeActivity(event: RecentActivityItem, appNamesById: Record<string, string>): string {
  const actor = event.actor ?? "someone";
  const fields = parseTarget(event.target);
  const appId = fields.application_id;
  const appName = appId ? appNamesById[appId] ?? appId : "an application";
  for (const pattern of PATTERNS) {
    if (pattern.test.test(event.action)) {
      return `${actor} ${pattern.describe(appName)}`;
    }
  }
  return `${actor} ${event.action}`;
}
