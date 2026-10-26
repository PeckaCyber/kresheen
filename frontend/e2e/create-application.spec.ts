import { expect, test, type Page } from "@playwright/test";

// See e2e/README.md for prerequisites (real backend, KRESHEEN_E2E_ADMIN_EMAIL/PASSWORD).
const ADMIN_EMAIL = process.env.KRESHEEN_E2E_ADMIN_EMAIL ?? "";
const ADMIN_PASSWORD = process.env.KRESHEEN_E2E_ADMIN_PASSWORD ?? "";

test.skip(!ADMIN_EMAIL || !ADMIN_PASSWORD, "KRESHEEN_E2E_ADMIN_EMAIL/PASSWORD not set -- see e2e/README.md");

test.beforeEach(async ({ page }) => {
  // The first-run model tour is a popup over the run page; mark it as seen.
  await page.addInitScript(() => localStorage.setItem("kresheen-tour-done", "1"));
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(ADMIN_EMAIL);
  await page.getByLabel(/password/i).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/(dashboard|applications)$/);
});

// Models are created through the API so each test starts from a known state without depending on the creation wizard
// (one test still drives the real wizard). Cookies from the logged-in page are shared with page.request.
async function csrfHeaders(page: Page) {
  const me = await (await page.request.get("/api/auth/me")).json();
  return { "X-CSRF-Token": me.csrf_token as string };
}

async function createModel(page: Page, name: string, manifest = MANIFEST_WITH_ONE_FINDING) {
  const headers = await csrfHeaders(page);
  const app = await (await page.request.post("/api/applications", { headers, data: { name } })).json();
  if (manifest) {
    await page.request.post(`/api/applications/${app.id}/data-sources`, {
      headers,
      data: { type: "manifest_upload", connection_details: { content: manifest, filename: "deployment.yaml" } },
    });
  }
  const run = await (await page.request.post(`/api/applications/${app.id}/runs`, { headers, data: {} })).json();
  await expect
    .poll(async () => (await (await page.request.get(`/api/applications/${app.id}/runs/${run.id}`)).json()).status, {
      timeout: 30000,
    })
    .toBe("completed");
  return { appId: app.id as string, runId: run.id as string };
}

async function openRun(page: Page, name: string, tab = "", manifest = MANIFEST_WITH_ONE_FINDING) {
  const { appId, runId } = await createModel(page, name, manifest);
  await page.goto(`/applications/${appId}/runs/${runId}${tab ? `/${tab}` : ""}`);
  return { appId, runId };
}

// "manifest_upload" is the default/first option in the create wizard, exercised
// here with a real k8s manifest containing one deliberately flagged
// misconfiguration (hostNetwork: true), matching engine/reasoning.py's
// _host_network_finding check.
const MANIFEST_WITH_ONE_FINDING = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  hostNetwork: true
  template:
    spec:
      containers:
        - name: web
          image: myregistry/web:1.0.0
`;

test("create a model with a manifest through the wizard, execute, and view the DFD and findings", async ({ page }) => {
  await page.goto("/applications");
  await page.getByRole("button", { name: "New threat model" }).first().click();
  await page.getByText("Upload files or connect a repository").click();

  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name").fill("Playwright Test App");
  await dialog.getByLabel(/Manifest files/).setInputFiles({
    name: "deployment.yaml",
    mimeType: "application/x-yaml",
    buffer: Buffer.from(MANIFEST_WITH_ONE_FINDING),
  });
  await dialog.locator("button[type=submit]").click();

  await expect(page).toHaveURL(/\/applications\/APP-[a-f0-9]+\/runs\/RUN-[a-f0-9]+/);

  await page.getByTestId("model-tab-diagram").click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();

  await page.getByTestId("model-tab-findings").click();
  await expect(
    page.getByRole("region", { name: "Findings" }).getByRole("row", { name: /host network namespace/ }),
  ).toBeVisible();

  // Returning to the diagram after another tab must still render it (React Flow resize handling).
  await page.getByTestId("model-tab-diagram").click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
});

test("threats: generated per DFD element with mitigations, and a status change sticks across a reload", async ({
  page,
}) => {
  const { appId, runId } = await openRun(page, "Playwright Threats App", "threats");

  const firstStatus = page.getByLabel(/^Status for /).first();
  await expect(firstStatus).toBeVisible();
  await expect(firstStatus).toHaveValue("open");

  // Expanding a row shows the description and suggested mitigations.
  await page.locator("tr[aria-expanded]").first().click();
  await expect(page.getByText("Suggested mitigations").first()).toBeVisible();

  await firstStatus.selectOption("mitigated");
  await expect(firstStatus).toHaveValue("mitigated");

  await page.goto(`/applications/${appId}/runs/${runId}/threats`);
  await expect(page.getByLabel(/^Status for /).first()).toHaveValue("mitigated");
});

test("threats: a custom threat that applies to every process generates, and a threat can be added by hand", async ({
  page,
}) => {
  // Unique per run: custom entries persist in the e2e database.
  const stamp = `T${Date.now()}`;

  // Custom KB entry that opts in to generation.
  await page.getByRole("link", { name: "Threat library" }).click();
  await page.getByRole("button", { name: "Add custom threat" }).click();
  await page.getByLabel("Name").fill(`Badge cloning ${stamp} at {name}`);
  await page.getByLabel("Description").fill("Cloned badges grant physical access.");
  await page.getByLabel("Generate this threat automatically on").selectOption("process");
  await page.getByLabel("Severity").selectOption("critical");
  await page.getByLabel("Suggested mitigations (one per line)").fill("Rotate badges");
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByLabel("Filter by source").selectOption("custom");
  await expect(
    page.getByRole("row", { name: new RegExp(stamp) }).getByRole("cell", { name: /^Process/ }),
  ).toBeVisible();

  await openRun(page, "Playwright Custom Threat App", "threats");
  await expect(page.getByText(new RegExp(`Badge cloning ${stamp} at `))).toBeVisible();
  await expect(page.getByText("Custom rule").first()).toBeVisible();

  // Attach a one-off threat by hand.
  await page.getByRole("button", { name: "Add threat" }).click();
  const modal = page.locator(".modal.show");
  // The modal re-initialises its form when background data (the element list, the threat list) arrives, which can
  // wipe what was just typed. Retry fill-and-submit until the modal actually closes.
  await expect(async () => {
    await modal.getByLabel("Title").fill("Insider exports customer data");
    await modal.getByLabel("Severity").selectOption("high");
    await modal.getByLabel(/Mitigations/).fill("DLP on egress");
    await modal.getByRole("button", { name: "Add threat" }).click();
    await expect(page.locator(".modal.show")).toHaveCount(0, { timeout: 2500 });
  }).toPass({ timeout: 20000 });
  await expect(page.getByText("Insider exports customer data")).toBeVisible();
  await expect(page.getByText("Manual", { exact: true })).toBeVisible();

  // It survives a reload, and can be deleted.
  await page.reload();
  await page.getByText("Insider exports customer data").click();
  await page.getByRole("button", { name: "Delete this threat" }).click();
  await expect(page.getByText("Insider exports customer data")).toHaveCount(0);
});

test("DFD edit mode: drag a component onto the diagram, drag-select it into a trust boundary, then delete it", async ({
  page,
}) => {
  await openRun(page, "Edit Mode Test App", "diagram");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();

  // The canvas frames itself on load; dropping before that settles would place the component at a different spot
  // each time. Wait for the viewport transform to stop changing.
  const viewport = page.locator(".react-flow__viewport");
  let lastTransform = "";
  await expect
    .poll(async () => {
      const transform = await viewport.evaluate((el) => (el as HTMLElement).style.transform);
      const settled = transform !== "" && transform === lastTransform;
      lastTransform = transform;
      return settled;
    })
    .toBe(true);
  // The group container of the existing namespace boundary and its component.
  await expect(page.locator(".react-flow__node")).toHaveCount(2);
  const initialNodeCount = 2;

  // react-bootstrap's Form.Check type="switch" renders an ARIA checkbox,
  // not a "switch" role, despite the visual styling -- confirmed against
  // a real render rather than assumed.
  await page.getByRole("checkbox", { name: /edit mode/i }).check();

  // Placing a component is a real HTML5 drag from a
  // palette button onto the canvas (not a form) -- Playwright's dragTo()
  // drives real browser mouse events, which is what's needed to actually
  // exercise the draggable/onDragStart/onDrop wiring, not something a
  // mocked/dispatched event would meaningfully cover.
  // Dropped away from the bottom-right corner deliberately -- that's where
  // the MiniMap control renders and intercepts pointer events for anything
  // underneath it, which is a real characteristic of this canvas users
  // could hit too, not something to paper over with a forced click here.
  const canvas = page.locator(".react-flow__pane");
  await page.getByRole("button", { name: "External Entity" }).dragTo(canvas, {
    targetPosition: { x: 120, y: 80 },
  });

  const nameInput = page.getByPlaceholder(/Name this External Entity/i);
  await expect(nameInput).toBeVisible();
  await nameInput.fill("Payment Gateway");
  await nameInput.press("Enter");

  // A manual component persists per-Application (not per-run) and the DFD
  // response merges it back in on every load -- confirms both the
  // create-route wiring and the merge logic in get_run_dfd, not just that
  // a network call succeeded. It also now carries a saved position (see
  // Asset.position_x/y) rather than snapping into the auto-grid.
  await expect(page.locator(".react-flow__node")).toHaveCount(initialNodeCount + 1);
  await expect(page.locator(".react-flow__node", { hasText: "Payment Gateway" })).toBeVisible();

  // Trust boundary tool: arm it, drag a selection box around the new node,
  // name the boundary in the reactive prompt that appears once something
  // is selected.
  await page.getByRole("button", { name: "⬚ Trust Boundary" }).click();
  const paymentNode = page.locator(".react-flow__node", { hasText: "Payment Gateway" });
  const box = await paymentNode.boundingBox();
  if (!box) throw new Error("Payment Gateway node has no bounding box");
  // Drag a rectangle that starts well outside the node and ends past its
  // far corner, so React Flow's SelectionMode.Partial picks it up
  // regardless of exactly where within the node the box's edge falls.
  await page.mouse.move(box.x - 40, box.y - 40);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width + 40, box.y + box.height + 40, { steps: 10 });
  await page.mouse.up();

  const boundaryNameInput = page.getByPlaceholder("Boundary name");
  await expect(boundaryNameInput).toBeVisible();
  await boundaryNameInput.fill("third-party");
  await page.getByRole("button", { name: "Apply" }).click();

  // The boundary group container renders its label as real text content --
  // this is the actual regression case for the parentId/extent grouping
  // wiring (@xyflow/react 12 renamed the older `parentNode` field), not
  // just that the node data shape is correct. Node count is now +2 vs.
  // the original baseline: +1 for the component, +1 for the boundary
  // group container it's now inside.
  await expect(page.getByText("third-party", { exact: true })).toBeVisible();
  // Only the new component is boxed in (the existing "prod" component sits outside the selection), so the new
  // boundary adds its group container next to the component itself.
  await expect(page.locator(".react-flow__node")).toHaveCount(initialNodeCount + 2);

  // Disarm the boundary tool before clicking the node -- otherwise the
  // click is interpreted as (the start and end of) a zero-size selection
  // drag rather than a normal node click.
  await page.getByRole("button", { name: "⬚ Trust Boundary" }).click();

  await page.locator(".react-flow__node", { hasText: "Payment Gateway" }).click();
  const offcanvas = page.getByTestId("element-inspector");
  await expect(offcanvas).toBeVisible();
  await expect(offcanvas.getByText("manually added")).toBeVisible();
  await offcanvas.getByTestId("inspector-tab-properties").click();
  await offcanvas.getByRole("button", { name: "Delete component" }).click();

  // The Offcanvas is also role="dialog" and still open behind this modal
  // (and contains the same "Delete component" button text) -- scope by
  // Bootstrap's own modal class to disambiguate rather than by text.
  const deleteDialog = page.locator(".modal.show").filter({ hasText: "Delete component" });
  await expect(deleteDialog).toBeVisible();
  await deleteDialog.getByRole("button", { name: "Delete", exact: true }).click();

  await expect(page.locator(".react-flow__node", { hasText: "Payment Gateway" })).toHaveCount(0);
  // The emptied boundary goes with it.
  await expect(page.locator(".react-flow__node")).toHaveCount(initialNodeCount);
});

test("DFD edit mode: undo/redo, and a trust boundary can be dragged and the position persists", async ({ page }) => {
  const { appId: applicationId, runId } = await openRun(page, "Undo Boundary Test App", "diagram");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  const initialNodeCount = await page.locator(".react-flow__node").count();
  const nodes = page.locator(".react-flow__node");

  const savedBoundaries = async () =>
    (await (await page.request.get(`/api/applications/${applicationId}/runs/${runId}/dfd`)).json()).boundaries;

  await page.getByRole("checkbox", { name: /edit mode/i }).check();
  await page.getByRole("button", { name: "External Entity" }).dragTo(page.locator(".react-flow__pane"), {
    targetPosition: { x: 120, y: 80 },
  });
  const nameInput = page.getByPlaceholder(/Name this External Entity/i);
  await nameInput.fill("Payment Gateway");
  await nameInput.press("Enter");
  await expect(nodes).toHaveCount(initialNodeCount + 1);

  // Undo / redo of a placement, via keyboard.
  await page.getByRole("button", { name: /Undo/ }).click();
  await expect(nodes).toHaveCount(initialNodeCount);
  await page.getByRole("button", { name: /Redo/ }).click();
  await expect(nodes).toHaveCount(initialNodeCount + 1);

  // Group it into a boundary (drag-select).
  await page.getByRole("button", { name: "⬚ Trust Boundary" }).click();
  const box = await nodes.filter({ hasText: "Payment Gateway" }).boundingBox();
  if (!box) throw new Error("Payment Gateway node has no bounding box");
  await page.mouse.move(box.x - 40, box.y - 40);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width + 40, box.y + box.height + 40, { steps: 10 });
  await page.mouse.up();
  await page.getByPlaceholder("Boundary name").fill("third-party");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("third-party", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "⬚ Trust Boundary" }).click();
  expect(await savedBoundaries()).toEqual([]);

  // Drag the boundary box by an empty patch of its own area (its top-left
  // corner, clear of the member component) and check it actually moved.
  const boundary = page.locator(".react-flow__node-boundary").filter({ hasText: "third-party" }); // the manifest's own "prod" namespace is a boundary too
  const before = await boundary.boundingBox();
  if (!before) throw new Error("boundary has no bounding box");
  await page.mouse.move(before.x + 8, before.y + 8);
  await page.mouse.down();
  await page.mouse.move(before.x + 8 + 160, before.y + 8 + 90, { steps: 10 });
  await page.mouse.up();
  const after = await boundary.boundingBox();
  expect(Math.round((after?.x ?? 0) - before.x)).toBeGreaterThan(100);
  await expect.poll(async () => (await savedBoundaries()).length).toBe(1);

  // A reload re-reads the persisted position rather than re-stacking.
  await page.reload();
  // (not an exact node count: a one-member boundary is sometimes drawn as an extra container node)
  await expect(nodes.filter({ hasText: "Payment Gateway" })).toHaveCount(1);
  await expect(page.getByText("third-party", { exact: true })).toBeVisible();
  expect((await savedBoundaries())[0].name).toBe("third-party");

  // History is per page load, so the reload emptied it; make an undoable edit.
  await page.getByRole("checkbox", { name: /edit mode/i }).check();
  const reloaded = await boundary.boundingBox();
  if (!reloaded) throw new Error("boundary has no bounding box after reload");
  await page.mouse.move(reloaded.x + 8, reloaded.y + 8);
  await page.mouse.down();
  await page.mouse.move(reloaded.x + 8 + 60, reloaded.y + 8 + 60, { steps: 10 });
  await page.mouse.up();
  await expect.poll(async () => (await savedBoundaries())[0].position_x).not.toBe(0);
  const moved = (await savedBoundaries())[0];
  await page.getByRole("button", { name: /Undo/ }).click();
  await expect.poll(async () => (await savedBoundaries())[0].position_x).not.toBe(moved.position_x);
  await page.getByRole("button", { name: /Redo/ }).click();
  await expect.poll(async () => (await savedBoundaries())[0].position_x).toBe(moved.position_x);

  // Delete the component, then undo brings it back.
  await page.locator(".react-flow__node", { hasText: "Payment Gateway" }).click();
  await page.getByTestId("element-inspector").getByTestId("inspector-tab-properties").click();
  await page.getByTestId("element-inspector").getByRole("button", { name: "Delete component" }).click();
  await page
    .locator(".modal.show")
    .filter({ hasText: "Delete component" })
    .getByRole("button", { name: "Delete", exact: true })
    .click();
  await expect(page.locator(".react-flow__node", { hasText: "Payment Gateway" })).toHaveCount(0);
  await page.getByRole("button", { name: /Undo/ }).click();
  await expect(page.locator(".react-flow__node", { hasText: "Payment Gateway" })).toBeVisible();
});

test("blank model: start with no data sources, draw, rename, label a connection, and edit a manual threat", async ({
  page,
}) => {
  await openRun(page, "Blank Model Test App", "diagram", "");

  // Edit mode is off on load (also for a blank model); the empty diagram shows a hint rather than an error.
  await expect(page.getByRole("checkbox", { name: /edit mode/i })).not.toBeChecked();
  await page.getByRole("checkbox", { name: /edit mode/i }).check();
  await expect(page.locator(".react-flow__node")).toHaveCount(0);

  const canvas = page.locator(".react-flow__pane");
  await page.getByRole("button", { name: "Process" }).dragTo(canvas, { targetPosition: { x: 100, y: 80 } });
  await page.getByPlaceholder(/Name this Process/i).fill("Web");
  await page.getByPlaceholder(/Name this Process/i).press("Enter");
  await expect(page.locator(".react-flow__node")).toHaveCount(1);
  await page.getByRole("button", { name: "Data Store" }).dragTo(canvas, { targetPosition: { x: 400, y: 80 } });
  await page.getByPlaceholder(/Name this Data Store/i).fill("DB");
  await page.getByPlaceholder(/Name this Data Store/i).press("Enter");
  await expect(page.locator(".react-flow__node")).toHaveCount(2);

  // Connect Web -> DB by dragging from Web's source handle to DB's target handle.
  const source = page.locator(".react-flow__node", { hasText: "Web" }).locator(".react-flow__handle.source");
  const target = page.locator(".react-flow__node", { hasText: "DB" }).locator(".react-flow__handle.target");
  await source.dragTo(target);
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);

  // Label the connection.
  const edgeDialog = page.locator(".modal.show").filter({ hasText: "Edit connection" });
  // force skips Playwright's stability wait, and the canvas can still be settling after the
  // connection is drawn, so retry the click until the dialog actually opens.
  await expect(async () => {
    await page.locator(".react-flow__edge").first().click({ force: true });
    await expect(edgeDialog).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 10000 });
  await edgeDialog.getByLabel("Label").fill("SQL");
  await edgeDialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.locator(".react-flow__edge-text", { hasText: "SQL" })).toBeVisible();

  // Rename a component; the diagram and its threats follow.
  await page.locator(".react-flow__node", { hasText: "Web" }).click();
  const panel = page.getByTestId("element-inspector");
  await panel.getByTestId("inspector-tab-properties").click();
  await panel.getByLabel("Name").fill("Storefront");
  await panel.getByRole("button", { name: "Rename" }).click();
  await expect(page.locator(".react-flow__node", { hasText: "Storefront" })).toBeVisible();
  await expect(page.locator(".react-flow__node", { hasText: "Web" })).toHaveCount(0);

  // Add a manual threat on it, then edit it.
  await page.locator(".react-flow__node", { hasText: "Storefront" }).click();
  await page.getByTestId("element-inspector").getByTestId("inspector-tab-threats").click();
  await page.getByTestId("element-inspector").getByRole("button", { name: "Add threat" }).click();
  const addDialog = page.locator(".modal.show").filter({ hasText: "Add threat" });
  await addDialog.getByLabel("Title").fill("Session theft");
  await addDialog.getByRole("button", { name: "Add threat" }).click();
  await page.getByTestId("element-inspector").getByText("Session theft").click();
  await page.getByTestId("element-inspector").getByRole("button", { name: "Edit this threat" }).click();
  const editDialog = page.locator(".modal.show").filter({ hasText: "Edit threat" });
  await editDialog.getByLabel("Title").fill("Session token theft");
  await editDialog.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByTestId("element-inspector").getByText("Session token theft")).toBeVisible();

  // Everything is persisted server-side: a reload shows the renamed component.
  await page.reload();
  await expect(page.locator(".react-flow__node", { hasText: "Storefront" })).toBeVisible();
});

test("properties: stating a fact adds a threat, Unknown removes it, and out of scope hides a component's threats", async ({
  page,
}) => {
  await openRun(page, "Properties Test App", "diagram", "");
  await page.getByRole("checkbox", { name: /edit mode/i }).check();

  await page.getByRole("button", { name: "Data Store" }).dragTo(page.locator(".react-flow__pane"), {
    targetPosition: { x: 200, y: 100 },
  });
  await page.getByPlaceholder(/Name this Data Store/i).fill("Vault");
  await page.getByPlaceholder(/Name this Data Store/i).press("Enter");
  const vault = page.locator(".react-flow__node", { hasText: "Vault" });
  await expect(vault).toBeVisible();

  const panel = page.getByTestId("element-inspector");
  const threat = "Data in Vault is not encrypted at rest";
  async function openVault() {
    await vault.click();
    await expect(panel).toBeVisible();
  }
  const threatsTab = () => panel.getByTestId("inspector-tab-threats").click();
  const propertiesTab = () => panel.getByTestId("inspector-tab-properties").click();
  async function saveProperties() {
    await panel.getByRole("button", { name: "Save properties" }).click();
    await expect(page.getByTestId("element-inspector")).toHaveCount(0);
  }

  // Not stated: only the generic threats.
  await openVault();
  await threatsTab();
  await expect(panel.getByText(threat)).toHaveCount(0);

  // State "not encrypted": the property threat appears, with the reason it was raised.
  await propertiesTab();
  await panel.getByLabel("Encrypted at rest", { exact: true }).selectOption("no");
  await saveProperties();
  await openVault();
  await threatsTab();
  await panel.getByText(threat).click();
  await expect(panel.getByText(/owner states: not encrypted at rest/).first()).toBeVisible();

  // Back to Unknown: it goes away again.
  await propertiesTab();
  await panel.getByLabel("Encrypted at rest", { exact: true }).selectOption("");
  await saveProperties();
  await openVault();
  await threatsTab();
  await expect(panel.getByText(threat)).toHaveCount(0);

  // Out of scope: the node is marked and its generated threats are hidden.
  await propertiesTab();
  await panel.getByLabel("Out of scope", { exact: true }).selectOption("yes");
  await panel.getByLabel("Reason out of scope").fill("Owned by another team");
  await saveProperties();
  await expect(vault).toContainText("(out of scope)");
  await openVault();
  await threatsTab();
  await expect(panel.getByText(/No threats generated for this element/)).toBeVisible();
  await expect(panel.getByText("Reason out of scope: Owned by another team")).toHaveCount(0); // editable in edit mode

  // The stated properties persist across a reload.
  await page.reload();
  await expect(page.locator(".react-flow__node", { hasText: "Vault" })).toContainText("(out of scope)");
});

test("export: every export link serves the right type with the session, and names the model", async ({ page }) => {
  const { appId, runId } = await createModel(page, "Export Test App", "");
  const headers = await csrfHeaders(page);
  await page.request.post(`/api/applications/${appId}/manual-assets`, {
    headers,
    data: { name: "Gateway", type: "process" },
  });
  await page.goto(`/applications/${appId}/runs/${runId}/overview`);

  await page.getByRole("button", { name: "Export" }).click();
  const hrefs = await page
    .locator(".dropdown-menu.show a")
    .evaluateAll((els) => els.map((el) => el.getAttribute("href") ?? "").filter((href) => href.startsWith("/api/")));
  const expected: Record<string, string> = {
    "report.pdf": "application/pdf",
    "report.docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "threats.csv": "text/csv",
    "findings.csv": "text/csv",
    "findings.sarif": "json",
    "dfd.svg": "image/svg+xml",
    "threatdragon.json": "json",
  };
  expect(hrefs.length).toBeGreaterThanOrEqual(Object.keys(expected).length);
  for (const [name, type] of Object.entries(expected)) {
    const href = hrefs.find((h) => h.includes(name));
    expect(href, `no menu link for ${name}`).toBeTruthy();
    const response = await page.request.get(href as string);
    expect(response.ok(), href).toBeTruthy();
    expect(response.headers()["content-type"], href).toContain(type);
    if (name === "dfd.svg") {
      expect(response.headers()["content-security-policy"]).toContain("default-src 'none'");
      expect(await response.text()).toContain("Gateway");
    }
    if (name === "threats.csv") expect(await response.text()).toContain("Gateway");
  }

  // The HTML report is not in the menu any more but the route still serves it, with its own strict CSP.
  const html = await page.request.get(`/api/applications/${appId}/runs/${runId}/report.html`);
  expect(html.headers()["content-security-policy"]).toContain("default-src 'none'");
  expect(await html.text()).toContain("Export Test App");
});

test("groups: create a group, add a model to it, and filter the list by group", async ({ page }) => {
  const stamp = Date.now();
  const groupName = `Team ${stamp}`;
  const groupedApp = `Grouped App ${stamp}`;
  const looseApp = `Loose App ${stamp}`;
  await page.goto("/applications");
  await page.getByRole("button", { name: "Manage groups" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Name").fill(groupName);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await expect(dialog.getByText(groupName)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  const headers = await csrfHeaders(page);
  const groups = (await (await page.request.get("/api/groups")).json()).groups as { id: string; name: string }[];
  const group = groups.find((g) => g.name === groupName);
  expect(group, "the group created in the dialog exists").toBeTruthy();
  await page.request.post("/api/applications", { headers, data: { name: groupedApp, group_id: group?.id } });
  await page.request.post("/api/applications", { headers, data: { name: looseApp } });

  await page.goto("/applications");
  await expect(page.getByRole("row", { name: new RegExp(groupedApp) })).toContainText(groupName);

  // Filter by the group: only its model remains. Ungrouped shows the other one.
  await page.getByLabel("Group", { exact: true }).selectOption({ label: groupName });
  await expect(page.getByRole("row", { name: new RegExp(groupedApp) })).toBeVisible();
  await expect(page.getByRole("row", { name: new RegExp(looseApp) })).toHaveCount(0);
  await page.getByLabel("Group", { exact: true }).selectOption({ label: "Ungrouped" });
  await expect(page.getByRole("row", { name: new RegExp(groupedApp) })).toHaveCount(0);
  await expect(page.getByRole("row", { name: new RegExp(looseApp) }).first()).toBeVisible();
});

test("delete model requires confirmation", async ({ page }) => {
  const name = `App To Delete ${Date.now()}`;
  const headers = await csrfHeaders(page);
  await page.request.post("/api/applications", { headers, data: { name } });
  await page.goto("/applications");
  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(row).toBeVisible();

  async function chooseDelete() {
    // A dismissed confirmation can leave the menu open; the toggle would then close it instead of opening it.
    if ((await page.locator(".dropdown-menu.show").count()) === 0) await row.locator("button.dropdown-toggle").click();
    await page.locator(".dropdown-menu.show").getByText("Delete", { exact: true }).click();
  }

  // Cancelling the browser confirmation keeps the model.
  page.once("dialog", (dialog) => void dialog.dismiss());
  await chooseDelete();
  await expect(row).toBeVisible();

  // Accepting deletes it.
  page.once("dialog", (dialog) => {
    expect(dialog.message()).toContain(name);
    void dialog.accept();
  });
  await chooseDelete();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toHaveCount(0);
});

test("a failed run names the bad data source, and the user can remove it and run again", async ({ page }) => {
  const headers = await csrfHeaders(page);
  const name = `Failed run ${Date.now()}`;
  const app = await (await page.request.post("/api/applications", { headers, data: { name } })).json();
  await page.request.post(`/api/applications/${app.id}/data-sources`, {
    headers,
    data: {
      type: "manifest_upload",
      connection_details: { content: "kind: Deployment\n  bad: [unclosed\n\t- : :\n", filename: "broken-deploy.yaml" },
    },
  });
  await page.request.post(`/api/applications/${app.id}/runs`, { headers, data: {} });

  // The model link lands on the failed run, not on "has not been run yet".
  await page.goto(`/models/${app.id}`);
  const failed = page.getByTestId("failed-run");
  await expect(failed).toBeVisible();
  await expect(failed.getByText("This run could not finish.")).toBeVisible();
  await expect(failed.getByText(/Could not read data source "broken-deploy\.yaml"/)).toBeVisible();
  await expect(page.getByRole("link", { name: "Back to Threat models" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Back to the last completed run" })).toHaveCount(0);

  // Remove the bad source, then run again.
  await failed.getByRole("button", { name: "Remove" }).first().click();
  await expect(failed.getByRole("table")).toHaveCount(0);
  await failed.getByRole("button", { name: "Run again" }).click();
  await expect(page.getByTestId("failed-run")).toHaveCount(0);
  await expect(page).toHaveURL(/\/applications\/[^/]+\/runs\/[^/]+$/);
  await expect(page.getByRole("heading", { name })).toBeVisible();
});
