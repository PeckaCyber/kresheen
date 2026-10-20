import { expect, test } from "@playwright/test";

// Real backend required -- not automated by playwright.config.ts (see its
// comment). Prerequisite steps are in e2e/README.md. Skips cleanly instead
// of failing/faking a pass when that prerequisite isn't set up.
const ADMIN_EMAIL = process.env.KRESHEEN_E2E_ADMIN_EMAIL ?? "";
const ADMIN_PASSWORD = process.env.KRESHEEN_E2E_ADMIN_PASSWORD ?? "";

test.skip(!ADMIN_EMAIL || !ADMIN_PASSWORD, "KRESHEEN_E2E_ADMIN_EMAIL/PASSWORD not set -- see e2e/README.md");

test("logs in and changes a setting that survives a reload", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
  await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page).toHaveURL(/\/(dashboard|applications)$/);
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();

  // Appearance is open by default; the theme is stored per browser and applied before first render.
  await page.getByRole("button", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");

  await page.getByRole("button", { name: "Light" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "light");
});
