# User guide

This guide follows the web interface. The same text is available inside the app under **Help**.

## What Kresheen does

Kresheen builds a threat model of a system. It has four parts:

1. A **data flow diagram**: components, the connections between them, and the trust boundaries they cross.
2. The **threats** that follow from that design.
3. Any **vulnerabilities** found in what you provided.
4. A ranked **action plan** for fixing them.

The threats come from built-in rules, so the same input always gives the same threats. You can state facts the tool could not read from your files, and the results become specific to your system.

The left menu has **Home**, **Threat models**, **Threat library**, **Settings** and **Help**.

## Create your first threat model

1. Open **Threat models**, choose **New threat model**, and pick a group (or Ungrouped).
2. Choose how to start:
   - **Describe your system.** Answer a few plain questions, or start from a template, and a starter model is drawn with your answers already stated as facts. No files needed. If AI assist is turned on for you, a box above the form can fill in answers from a description you paste (see [ai.md](ai.md)).
   - **Upload infrastructure files** or **Connect a GitHub repository.** See [data-sources.md](data-sources.md).
   - **Import a diagram** from Threat Dragon, draw.io, Mermaid or Threagile.
   - **Draw it yourself** on a blank canvas.
3. The model runs as soon as it is created. It builds the components and flows, then generates threats.
4. Work across the tabs of the model page: check the **Diagram**, answer the questions on **Overview**, then follow the **Action plan**.

New here? **Explore a sample model** on the first-run page creates an ordinary model you can edit or delete, so you can see what results look like.

## Home

**Home** (also reachable by clicking the Kresheen name) summarises every model you can see. Click a tile or panel for the detail.

- Tiles: **Models**, **Open threats**, **High + critical open**, **Addressed**, **Avg completeness** and **Needs attention** (models that are stale or never reviewed).
- **Threat trend**: open threats over time. A snapshot is recorded whenever Home is opened, or a run or threat status changes, so the history starts the first time you open it. Choose 7d, 30d, 90d or All at the top.
- **Open threats by risk**, **Triage progress** by group, a **Needs attention** table (every model, worst risk first), **Review status**, and, for owners, **Recent activity**.

## The model page

The page has a header (the model's name, a run picker, **Re-run**, **Mark as reviewed**, **Export**), a strip of six numbers, and tabs: **Overview**, **Diagram**, **Threats**, **Action plan**, **Findings** and **Model settings**. Each number in the strip jumps to the tab that explains it. **Re-run** runs the model again against its current sources and facts. The run picker shows earlier runs.

### Overview

- **What to do next**: the top few completeness questions, which you can answer in place, and the top few fixes from the action plan.
- A risk breakdown, attack paths, and what changed since the last run.
- The full **Model completeness** check behind "Show all questions".

**Model completeness** lists facts the model does not state yet: what data a store holds, whether a service authenticates callers, whether traffic crossing a trust boundary is encrypted. Each has a one-click answer. Unstated facts get the generic result, so answering them makes the threats and plan specific to your system.

**Attack paths** show how something outside can reach a data store by crossing trust boundaries. A data store with a stated data classification is treated as a crown jewel.

**What changed since the last run** compares two runs: components, flows, threats and findings that are new or gone. Components are matched by name.

### Diagram

The canvas fills the window. A model can have several diagrams, each a focused view of the same model. Switch or create them with the tabs above the canvas.

1. Turn on **Edit mode** (it is off every time you open a model). Add processes, data stores, external entities and trust boundaries, and drag between components to connect them.
2. Undo and redo with the toolbar or Ctrl-Z and Ctrl-Y. Deleting a hand-drawn component can be undone.
3. Click any component to open its side panel. Rename it, set its trust boundary, and state facts about it. You do not need Edit mode for stating facts.

In the side panel the **Show on this diagram** button is lit when the component appears on the diagram you are viewing. Click it to hide the component on this diagram only. Hiding changes no threats, findings or reports. **Delete component** removes a hand-drawn component from the whole model.

### Threats

Each row is tagged:

- **observed**: found in your configuration, or backed by a scanner finding,
- **specific**: applies because of a fact about your design, or
- **generic**: a checklist item for any element of that type.

Generic items are hidden behind "Show the generic checklist" once anything more specific exists. Risk is impact times likelihood. Evidence such as a known-exploited vulnerability raises likelihood.

Filter by element, status, risk, methodology or category. The built-in rules use STRIDE. Kresheen Pro (coming soon) extends the methodology coverage; any extra methodologies can be turned on per model in **Model settings**.

**Triage:**

1. Set a threat to **mitigated**, **accepted** or **not applicable** from its row. Accepting or dismissing needs a reason. To change several at once, tick them and use the bar that appears.
2. Click a component on the diagram to see only its threats in the side panel. **View all threats for this element** opens the full list already filtered to it.
3. **Mark as reviewed** at the top of the page records who last signed the model off. It appears in exported reports.

**Add threat** creates a threat of your own on an element. The **Custom** methodology takes a free-text category.

### Action plan

Groups your open threats by the fix that addresses them and ranks the fixes: misconfigurations found in your configuration first, then fixes specific to your design, then generic hardening. Mark each fix **To do**, **In progress**, **Done** or **Won't do** (with a reason). **Download checklist (CSV)** exports it.

### Findings

Scanner results, such as vulnerabilities from a repository scan, with the software bill of materials as a second card when one was produced.

### Model settings

**Data sources** (add or remove, then re-run) and **Model info**: name, description, owner, reviewer, contributors and methodologies.

## Exporting

The **Export** menu on the model page offers:

- **Report (PDF)** and **Report (Word)**: the full threat model, including model info, diagram tables, threats, action plan and findings. The diagram appears as component and flow tables in these files.
- **Threats (CSV)**, **Findings (CSV)** and **Findings (SARIF)**.
- **Diagram (SVG)**, **Diagram (PNG)** and **Diagram (JSON)**, the last in Threat Dragon format for other threat modeling tools.

The HTML report and the action plan CSV are also available through the API (`report.html` and `action-plan.csv` under a run). Every export is recorded in the audit log.

## Threat library

The **Threat library** lists the built-in rules, filterable by methodology and entity type, and holds threats of your own. **Add custom threat** creates an entry. If you choose what it applies to, it generates threats on every matching element like a built-in rule. Otherwise it is reference only, and you can attach it to a specific component or flow from a model's **Threats** tab. The built-in rules carry MITRE ATT&CK and CWE ids. The MITRE and CWE feed lists are empty in this release.

## Groups

Threat models are organised into groups (teams). A group is a shared workspace: every signed-in user can see and edit its threat models. The person who created a group, and owners, can rename or delete it. **Manage groups** is on the Threat models page.

## Settings

Each section is collapsed. Click a heading to expand it.

- **Appearance**: light, dark, or match your system. Saved in this browser only.
- **Account**: change your own password (at least 12 characters). Changing it signs out your other sessions and revokes your API tokens.
- **Users** (owners only): add a teammate (a one-time password is shown once), change a role between owner and member, or deactivate someone. At least one active owner must remain.
- **API tokens**: tokens for the CI gate (`kresheen ci`). A token is shown once when created. It acts as you but can only list models and start and read runs. It expires after 90 days unless you choose 30 days, 1 year or never when you create it. See [ci-integration.md](ci-integration.md).
- **AI assist**: see below.
- **Audit log** (owners only): every change made through the dashboard or an API token, newest first. Request contents are never recorded. The page shows how many entries are held against the limit, for example `30 / 2000 entries`, and the oldest are dropped once it is reached. Operators can also delete old entries automatically (`KRESHEEN_AUDIT_RETENTION_DAYS`) or by hand (`kresheen audit-prune`).

## AI assist (experimental)

An optional helper, off by default. Rule-based analysis works fully without it. The owner turns it on under **Settings**, **AI assist**. Each person who wants it adds their own Anthropic API key there and picks a model. An administrator can force it off for the whole server. Two actions exist: **Describe your system (AI, experimental)** in the guided setup, and **Explain (AI, experimental)** on a threat. What is sent, and the safeguards, are in [ai.md](ai.md).
