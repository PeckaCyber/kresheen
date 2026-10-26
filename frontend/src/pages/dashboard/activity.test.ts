import { describe, expect, it } from "vitest";
import { describeActivity } from "./activity";

const names = { "APP-1": "Sample shop" };

describe("describeActivity", () => {
  it("describes a run", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: "t@example.com",
      action: "POST /api/applications/{application_id}/runs",
      target: "application_id=APP-1",
    };
    expect(describeActivity(event, names)).toBe("t@example.com ran Sample shop");
  });

  it("describes a data source addition", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: "t@example.com",
      action: "POST /api/applications/{application_id}/data-sources",
      target: "application_id=APP-1",
    };
    expect(describeActivity(event, names)).toBe("t@example.com added a data source to Sample shop");
  });

  it("describes a threat status change", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: "t@example.com",
      action: "PUT /api/applications/{application_id}/runs/{run_id}/threats/status",
      target: "application_id=APP-1, run_id=R-1",
    };
    expect(describeActivity(event, names)).toBe("t@example.com changed a threat status in Sample shop");
  });

  it("describes creating a threat model", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: "t@example.com",
      action: "POST /api/applications",
      target: "",
    };
    expect(describeActivity(event, names)).toBe("t@example.com created a threat model");
  });

  it("falls back to the raw method and path for an unmapped action", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: "t@example.com",
      action: "POST /api/applications/{application_id}/exports",
      target: "application_id=APP-1",
    };
    expect(describeActivity(event, names)).toBe("t@example.com POST /api/applications/{application_id}/exports");
  });

  it("falls back to an application id it doesn't recognise, and 'someone' for a null actor", () => {
    const event = {
      at: "2026-09-26T00:00:00Z",
      actor: null,
      action: "POST /api/applications/{application_id}/runs",
      target: "application_id=APP-9",
    };
    expect(describeActivity(event, names)).toBe("someone ran APP-9");
  });
});

describe("describeActivity: users and bulk status", () => {
  it("describes user management and bulk triage in plain language", () => {
    const base = { at: "2026-09-26T00:00:00Z", actor: "a@example.com" };
    expect(describeActivity({ ...base, action: "POST /api/users", target: "" }, {})).toBe("a@example.com added a user");
    expect(
      describeActivity(
        {
          ...base,
          action: "PUT /api/applications/{application_id}/runs/{run_id}/threats/status/bulk",
          target: "application_id=APP-1",
        },
        { "APP-1": "Shop" },
      ),
    ).toBe("a@example.com changed several threat statuses in Shop");
  });
});
