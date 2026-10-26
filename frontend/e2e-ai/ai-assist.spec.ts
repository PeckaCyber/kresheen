import { expect, test } from "@playwright/test";

// AI-on end-to-end test (4A.6). Runs only with playwright.ai.config.ts, against a backend started with
// KRESHEEN_AI_BASE_URL pointing at tests/support/anthropic_stub.py and a KRESHEEN_SECRET_KEY. See e2e/README.md.
const ADMIN_EMAIL = process.env.KRESHEEN_E2E_ADMIN_EMAIL ?? "";
const ADMIN_PASSWORD = process.env.KRESHEEN_E2E_ADMIN_PASSWORD ?? "";

test.skip(!ADMIN_EMAIL || !ADMIN_PASSWORD, "KRESHEEN_E2E_ADMIN_EMAIL/PASSWORD not set -- see e2e/README.md");

const TEST_KEY = "sk-ant-test-0000000000000000";
const DESCRIPTION =
  "A patient portal where patients log in to see health records and pay bills by card; staff use an admin panel.";

test.beforeEach(async ({ page }) => {
  // The first-run model tour is a popup over the run page; mark it as seen.
  await page.addInitScript(() => localStorage.setItem("kresheen-tour-done", "1"));
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
  await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/(dashboard|applications)$/);
});

// The AI assist card is collapsed on Settings until its header is clicked.
async function openAiCard(page: import("@playwright/test").Page) {
  await page.goto("/settings");
  const card = page.locator("#ai");
  await card.getByRole("button", { name: /AI assist/ }).click();
  await expect(card.getByText("Experimental", { exact: true })).toBeVisible();
  return card;
}

// Opens the guided setup from the threat models list (same path as the wizard tests in create-application.spec.ts).
async function openGuidedSetup(page: import("@playwright/test").Page) {
  await page.goto("/applications");
  await page.getByRole("button", { name: "New threat model" }).first().click();
  await page.getByText("Describe your system (guided)", { exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Describe your system", { exact: true })).toBeVisible();
  return dialog;
}

test("AI assist: turn on, add a key, draft the guided setup, explain a threat, then turn off", async ({ page }) => {
  // 1. Owner opens Settings and finds the AI assist card.
  const card = await openAiCard(page);

  // 2. Turn the instance switch on. The switch is controlled, so click() (not check()).
  // The spec starts from a fresh database (switch off). Re-running on the same database fails here, by design.
  const toggle = page.getByLabel("Turn on AI assist for this instance", { exact: true });
  await expect(toggle).not.toBeChecked();
  await toggle.click();
  await expect(toggle).toBeChecked();

  // 3. Accept the notice, add a key, test it, pick the stub model and save.
  await card.getByRole("button", { name: "I understand" }).click();
  await card.getByLabel("Your Anthropic API key").fill(TEST_KEY);
  await card.getByRole("button", { name: "Test key" }).click();
  await expect(page.getByText("Key works. 1 models available.")).toBeVisible();
  await card.getByLabel("Model", { exact: true }).selectOption("stub-model");
  await card.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("AI settings saved")).toBeVisible();

  // 4. Guided setup: describe the system and draft answers. The stub returns a canned draft.
  const dialog = await openGuidedSetup(page);
  const aiBox = dialog.getByTestId("intake-ai-box");
  await expect(aiBox).toBeVisible();
  await expect(aiBox.getByText("Describe your system (AI, experimental)")).toBeVisible();
  await aiBox.getByLabel("System description").fill(DESCRIPTION);
  await aiBox.getByRole("button", { name: "Draft answers" }).click();
  await expect(dialog.getByTestId("ai-tag").first()).toBeVisible();
  await expect(dialog.getByText("Suggested by AI").first()).toBeVisible();

  // 5. Submit the wizard, then explain one threat in the resulting run.
  await dialog.getByRole("button", { name: "Create threat model" }).click();
  await expect(page).toHaveURL(/\/applications\/APP-[a-f0-9]+\/runs\/RUN-[a-f0-9]+/);
  const runPath = new URL(page.url()).pathname;
  await page.goto(`${runPath}/threats`);

  await page.locator("tr[aria-expanded]").first().click();
  await page.getByRole("button", { name: "Explain (AI, experimental)" }).first().click();
  const explanation = page.getByLabel("AI explanation").first();
  await expect(explanation).toContainText("This threat means");
  await expect(explanation.getByText("AI-generated, may be wrong. Not saved.")).toBeVisible();

  // 6. Back to Settings: turn the switch off. The per-user key section goes, and the guided setup has no AI box.
  const cardAgain = await openAiCard(page);
  await expect(cardAgain.getByTestId("ai-key-section")).toBeVisible();
  const toggleAgain = page.getByLabel("Turn on AI assist for this instance", { exact: true });
  await toggleAgain.click();
  await expect(toggleAgain).not.toBeChecked();
  await expect(page.getByTestId("ai-key-section")).toHaveCount(0);

  await expect.poll(async () => (await (await page.request.get("/api/capabilities")).json()).ai.enabled).toBe(false);
  const guided = await openGuidedSetup(page);
  await expect(guided.getByRole("textbox", { name: "Name", exact: true })).toBeVisible();
  await expect(guided.getByTestId("intake-ai-box")).toHaveCount(0);
});
