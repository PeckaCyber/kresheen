import type { ReactNode } from "react";
import { Link, Navigate, useParams } from "react-router-dom";

// A small docs site: a sidebar of topics, one short page each, with previous/next links.
// Keep every claim here true of what is built today; update the relevant topic
// whenever a user-facing feature ships.

interface Topic {
  id: string;
  title: string;
  summary: string;
  body: ReactNode;
}

interface Section {
  title: string;
  topics: Topic[];
}

function Steps({ children }: { children: ReactNode }) {
  return <ol className="help-steps">{children}</ol>;
}

function Note({ children }: { children: ReactNode }) {
  return <div className="border-start border-3 border-info bg-body-tertiary p-3 mb-3 small">{children}</div>;
}

const SECTIONS: Section[] = [
  {
    title: "Getting started",
    topics: [
      {
        id: "overview",
        title: "What this tool does",
        summary: "How a threat model is built, and what you get out of it.",
        body: (
          <>
            <p>
              Kresheen builds a threat model of a system: a data flow diagram (components, the connections between them
              and the trust boundaries they cross), the threats that follow from that design, any vulnerabilities found
              in what you provided, and a ranked plan for fixing them.
            </p>
            <p>
              The threats come from built-in rules, so the same input always gives the same threats. You can add facts
              the tool could not read from your files, and the results become specific to your system.
            </p>
            <Note>
              Start with <Link to="/help/first-model">Create your first threat model</Link>, or open{" "}
              <strong>Home</strong> to see everything at a glance.
            </Note>
          </>
        ),
      },
      {
        id: "first-model",
        title: "Create your first threat model",
        summary: "Three ways to start, and what happens when you create one.",
        body: (
          <>
            <Steps>
              <li>
                Open <strong>Threat models</strong>, pick a group (or Ungrouped) and choose{" "}
                <strong>New threat model</strong>.
              </li>
              <li>
                Choose how to start:
                <ul>
                  <li>
                    <strong>Describe your system</strong>: answer a few plain questions, or start from a template. A
                    starter model is drawn with your answers already stated as facts. No files needed.
                  </li>
                  <li>
                    <strong>Upload infrastructure files</strong>, <strong>connect a GitHub repository</strong> or{" "}
                    <strong>import a diagram</strong>: see <Link to="/help/data-sources">Data sources</Link>.
                  </li>
                  <li>
                    <strong>Draw it yourself</strong>: a blank canvas.
                  </li>
                </ul>
              </li>
              <li>
                The model runs as soon as it is created. It builds the components and flows, then generates threats.
              </li>
              <li>
                Work across the run page's tabs: check the <strong>Diagram</strong>, answer the questions on{" "}
                <strong>Overview</strong>, then follow the <strong>Action plan</strong> tab. See{" "}
                <Link to="/help/results">Reading the results</Link>.
              </li>
            </Steps>
            <p>
              New here? Open a sample to see what results look like: <strong>Online shop</strong> (drawn by hand),{" "}
              <strong>Kubernetes app</strong> (built from uploaded manifests) or <strong>AWS app</strong> (built from a
              Terraform plan). They are on the first-run page and under <strong>New threat model</strong>. Each sample
              is an ordinary model you can edit or delete; the Kubernetes and AWS ones have a few weaknesses planted on
              purpose.
            </p>
          </>
        ),
      },
    ],
  },
  {
    title: "Working with a model",
    topics: [
      {
        id: "dashboard",
        title: "The Dashboard",
        summary: "The cross-application overview and the threat trend.",
        body: (
          <>
            <p>
              <strong>Home</strong> (also reachable by clicking the Kresheen name) summarizes every threat model you can
              see. Click a tile or panel for the detail in a side panel:
            </p>
            <ul>
              <li>
                <strong>Models</strong>: all of them, with their group.
              </li>
              <li>
                <strong>Open threats</strong> and <strong>High + critical open</strong>: how many are outstanding, and
                the models with the most first.
              </li>
              <li>
                <strong>Addressed</strong>: the share of threats that are mitigated, accepted or not applicable.
              </li>
              <li>
                <strong>Avg completeness</strong>: how much of each model&apos;s key facts are stated.
              </li>
              <li>
                <strong>Needs attention</strong>: models whose data sources changed since the last run (or that never
                ran), or that were never reviewed.
              </li>
            </ul>
            <p>
              <strong>Threat trend</strong> charts open threats across your models over time, over the 7d, 30d, 90d or
              All range you pick at the top. A snapshot is recorded whenever Home is opened, or a run or threat status
              changes, so the history starts from the first time you open it and fills in from there. Further panels
              show open threats by risk, triage progress by group, every model with its worst risk, and review status.
              Owners also see recent activity.
            </p>
          </>
        ),
      },
      {
        id: "diagram",
        title: "Editing the diagram",
        summary: "Edit mode, trust boundaries, and showing or hiding parts of a diagram.",
        body: (
          <>
            <p>
              The run page's <strong>Diagram</strong> tab holds the canvas. It stays sized to fill the window, so a busy
              model still has room to work in.
            </p>
            <Steps>
              <li>
                Turn on <strong>Edit mode</strong> (it is always off when you open a model). Add processes, data stores,
                external entities and trust boundaries, and drag between components to connect them.
              </li>
              <li>Undo and redo with the toolbar or Ctrl-Z / Ctrl-Y. Deleting a hand-drawn component can be undone.</li>
              <li>
                Click any component to open its side panel: rename it, set its trust boundary, and state facts about it.
                You do not need Edit mode for stating facts.
              </li>
            </Steps>
            <h3 className="h6 mt-4">Several diagrams of one model</h3>
            <p>
              A model can have more than one diagram, each a focused view of the same model. Switch or create them with
              the tabs above the canvas (within the Diagram tab, separate from the run page's own tabs). In the side
              panel, the <strong>Show on this diagram</strong> button is lit when the component appears on the diagram
              you are viewing. Click it to hide the component on this diagram only; click it again to bring it back.
              Threats, findings and reports are not affected by hiding.
            </p>
            <Note>
              <strong>Delete component</strong> removes a hand-drawn component from the whole model, not just the
              current diagram. Use the Show button to only hide it here.
            </Note>
          </>
        ),
      },
      {
        id: "results",
        title: "Reading the results",
        summary: "Completeness, the action plan, threats, and how risk is ranked.",
        body: (
          <>
            <p>
              The run page is a header (the model's name, a stat strip of 6 numbers) and tabs: Overview, Diagram,
              Threats, Action plan, Findings and Model settings. Each tile in the stat strip jumps to the tab that
              explains it.
            </p>
            <h3 className="h6">Overview</h3>
            <p>
              The default tab: <strong>What to do next</strong> (the top few completeness questions, answerable inline,
              and the top few actions from the action plan), a risk breakdown, attack paths, what changed since the last
              run, and the full <strong>Model completeness</strong> check behind a "Show all questions" disclosure.
            </p>
            <h3 className="h6 mt-4">Model completeness</h3>
            <p>
              Lists facts the model does not state yet: what data a store holds, whether a service authenticates
              callers, whether traffic crossing a trust boundary is encrypted. Each has a one-click answer. Unstated
              facts get the generic result, so answering them makes the threats and plan specific to your system.
            </p>
            <h3 className="h6 mt-4">Action plan (tab)</h3>
            <p>
              Groups your open threats by the fix that addresses them and ranks the fixes: misconfigurations found in
              your configuration first, then fixes specific to your design, then generic hardening. Mark each fix to do,
              in progress, done, or won&apos;t do (with a reason). You can download it as a checklist.
            </p>
            <h3 className="h6 mt-4">Threats (tab)</h3>
            <p>
              Each row is tagged <em>observed</em> (found in your configuration or backed by a scanner finding),{" "}
              <em>specific</em> (applies because of a fact about your design) or <em>generic</em> (a checklist item for
              any element of that type). Generic items are hidden behind &quot;Show the generic checklist&quot; once
              anything more specific exists. Risk is impact times likelihood; evidence such as a known-exploited
              vulnerability raises likelihood.
            </p>
            <h3 className="h6 mt-4">Findings and Model settings</h3>
            <p>
              <strong>Findings</strong> lists scanner results, with the software bill of materials as a second card when
              one was produced. <strong>Model settings</strong> holds data sources and model info (owner, reviewer,
              methodologies).
            </p>
          </>
        ),
      },
      {
        id: "triage",
        title: "Triaging threats",
        summary: "Setting statuses, filtering by element, and signing off a model.",
        body: (
          <>
            <Steps>
              <li>
                Open <strong>Threats</strong> on the run page. Filter by element, status, risk, methodology or category.
              </li>
              <li>
                Set a threat to mitigated, accepted or not applicable from its row. Accepting or dismissing needs a
                reason. To change several at once, tick them and use the bar that appears.
              </li>
              <li>
                Click a component on the diagram to see only its threats in the side panel. Rows are compact; expand one
                for its description, status and details. <strong>View all threats for this element</strong> opens the
                full list already filtered to that component.
              </li>
              <li>
                <strong>Mark as reviewed</strong> at the top of the page records who last signed the model off; it
                appears in exported reports.
              </li>
            </Steps>
          </>
        ),
      },
      {
        id: "exports",
        title: "Exporting",
        summary: "Reports, spreadsheets, scanner formats and diagram files.",
        body: (
          <>
            <p>
              The <strong>Export</strong> menu on the run page offers:
            </p>
            <ul>
              <li>
                <strong>Report (PDF)</strong> and <strong>Report (Word)</strong>: the full threat model.
              </li>
              <li>
                <strong>Threats (CSV)</strong>, <strong>Findings (CSV)</strong> and <strong>Findings (SARIF)</strong>.
              </li>
              <li>
                <strong>Diagram (SVG)</strong>, <strong>Diagram (PNG)</strong> and <strong>Diagram (JSON)</strong>, the
                last for use in other threat modeling tools.
              </li>
            </ul>
          </>
        ),
      },
    ],
  },
  {
    title: "Inputs",
    topics: [
      {
        id: "data-sources",
        title: "Data sources",
        summary: "What can be read, and what is only stored.",
        body: (
          <>
            <p>These are read and analysed:</p>
            <ul>
              <li>
                A Terraform plan (JSON, AWS-style resources) or Kubernetes YAML files. Secret values are redacted before
                anything is stored.
              </li>
              <li>
                A GitHub repository. Plain Kubernetes manifests in it yield components, and a vulnerability scan (Grype)
                runs if available. An optional GitHub token for a private repository is stored with the data source: use
                a read-only token limited to that repository.
              </li>
              <li>
                A diagram: Threat Dragon JSON, draw.io, a Mermaid flowchart or a Threagile model. Threats already listed
                in the file are not imported; they are worked out from the model.
              </li>
            </ul>
            <Note>
              Additional documentation files, images, Helm charts, Terraform <code>.tf</code> files and diagram formats
              not listed above are stored with the model but <strong>not read</strong>. The run page says so in an amber
              banner, and the Data Sources section shows the status of each input. A model with no threats from such an
              input has not been checked; it is not a clean result. Describe the system, add components by hand, or
              upload a manifest instead.
            </Note>
            <Note>
              Some inputs are read only in part. A GitHub repository is also checked for known vulnerabilities in its
              dependencies; if that scan could not run (the scanner is missing, timed out or failed), or a diagram is
              larger than the limit (500 components, 2000 flows) and only the first part was read, the run page, the
              Data Sources section and the report say so under <strong>Incomplete</strong>. In that case a short list,
              or &quot;no vulnerabilities&quot;, means those parts were not checked, not that nothing is there.
            </Note>
            <p>
              You can add or remove data sources on an existing model and re-run it.{" "}
              <strong>What changed since the last run</strong> shows the difference.
            </p>
            <p>
              If a data source cannot be read, the run fails and the run page names that source. Remove or replace it on
              that page, then choose <strong>Run again</strong>.
            </p>
          </>
        ),
      },
    ],
  },
  {
    title: "Administration",
    topics: [
      {
        id: "settings",
        title: "Settings",
        summary: "Appearance, account, users, API tokens and the audit log.",
        body: (
          <>
            <p>
              Each section is collapsed; click a heading to expand it. Settings holds everything you visit occasionally
              rather than every day:
            </p>
            <ul>
              <li>
                <strong>Appearance</strong>: light, dark, or match your system. Also available from the theme toggle in
                the sidebar's user menu.
              </li>
              <li>
                <strong>Account</strong>: change your own sign-in password (at least 12 characters). Your other sessions
                are signed out and your API tokens are revoked.
              </li>
              <li>
                <strong>Users</strong> (owners only): add a teammate, change a role, or deactivate someone.
              </li>
              <li>
                <strong>API tokens</strong>: tokens for the CI gate (<code>kresheen ci</code>). A token is shown once
                when created. It can only list models and start and read runs (not change models, users, connectors or
                tokens), it expires after 90 days unless you choose another expiry (or never) when you create it, and it
                is revoked when you change your password.
              </li>
              <li>
                <strong>Audit log</strong> (owners only): who changed what. See{" "}
                <Link to="/help/audit-log">Audit log</Link>.
              </li>
            </ul>
          </>
        ),
      },
      {
        id: "ai-assist",
        title: "AI assist (experimental)",
        summary: "An optional helper that uses your own Anthropic API key. Off by default.",
        body: (
          <>
            <p>
              AI assist is an optional, experimental helper. It is off by default. Kresheen&apos;s threat analysis is
              rule-based and works fully without it.
            </p>
            <p>To turn it on:</p>
            <Steps>
              <li>
                The owner turns on AI assist for the whole installation under <strong>Settings</strong>, in the{" "}
                <strong>AI assist</strong> card.
              </li>
              <li>
                Each person who wants it adds their own Anthropic API key in the same card and picks a model. An
                organisation-level key that is not tied to one workspace also needs its workspace ID.
              </li>
              <li>
                An administrator can force it off for the whole server with the <code>KRESHEEN_AI_DISABLED</code>{" "}
                setting.
              </li>
            </Steps>
            <p>There are two actions:</p>
            <ul>
              <li>
                <strong>Describe your system (AI, experimental)</strong>, in the guided setup: paste a description or
                upload a text or Markdown file, and AI suggests answers for the guided setup form. Suggested answers are
                marked, and nothing is created until you review the form and submit it.
              </li>
              <li>
                <strong>Explain (AI, experimental)</strong>, on a threat: a plain-language explanation of a threat,
                shown on screen and not saved. Very long property values on the component are shortened, or left out,
                before sending, and the explanation says so.
              </li>
            </ul>
            <p>
              The text you give it is sent to Anthropic with your own key. That is your description or document, or the
              threat and its component details. Credential-shaped values are removed before sending. Nothing else from
              your models is sent.
            </p>
            <p>Some safeguards:</p>
            <ul>
              <li>Text you send is treated as data, not instructions.</li>
              <li>
                If it contains wording aimed at automated tools (for example &quot;ignore previous instructions&quot;),
                you see a warning and the event is recorded in the audit log.
              </li>
              <li>AI can never remove or downgrade a threat.</li>
              <li>AI output can be wrong, so review it.</li>
            </ul>
            <p>
              To turn it off, remove your key in <strong>Settings</strong>, or the owner turns off AI assist for
              everyone. When it is off, no AI buttons appear and nothing is sent.
            </p>
          </>
        ),
      },
      {
        id: "audit-log",
        title: "Audit log",
        summary: "Who changed what, and how many entries are kept.",
        body: (
          <>
            <p>
              Owners find an <strong>Audit log</strong> card under <strong>Settings</strong>, linking to every change
              made through the dashboard or an API token, newest first. Request contents are never recorded.
            </p>
            <p>
              The audit log page shows how many entries are held against the limit, for example{" "}
              <code>30 / 2000 entries</code>. Once the limit is reached the oldest entries are dropped. You can also
              delete entries older than a number of days automatically with <code>KRESHEEN_AUDIT_RETENTION_DAYS</code>.
            </p>
          </>
        ),
      },
      {
        id: "teams",
        title: "Groups and access",
        summary: "Organizing threat models by team.",
        body: (
          <>
            <p>
              Threat models are organized into groups (teams). A group is a shared workspace: every signed-in user can
              see and edit its threat models. The person who created a group, and owners, can rename or delete it.
            </p>
          </>
        ),
      },
    ],
  },
  {
    title: "Reference",
    topics: [
      {
        id: "threat-kb",
        title: "Threat library",
        summary: "The built-in rules, and adding your own threats.",
        body: (
          <>
            <p>
              The <strong>Threat library</strong> lists the built-in rules that generate threats on every matching
              element of a diagram: STRIDE threats per element, written for this project, and a few misconfiguration
              checks for Kubernetes and AWS. Kresheen Pro (coming soon) extends the threat knowledge base, including the
              full set of misconfiguration checks, and the methodology coverage. You can filter by methodology and by
              the kind of element. The rules carry MITRE ATT&amp;CK and CWE ids where they apply; the library itself is
              not pre-loaded with MITRE or CWE entries.
            </p>
            <p>
              Use <strong>Add custom threat</strong> for risks specific to your organization. If you choose what it
              applies to, it generates threats on every matching element like a built-in rule. Otherwise it is for
              reference, and you can attach it to a specific component or flow from a model&apos;s Threats tab.
            </p>
          </>
        ),
      },
    ],
  },
];

const ALL_TOPICS = SECTIONS.flatMap((section) => section.topics);

export function HelpPage() {
  const { topic } = useParams<{ topic?: string }>();
  if (!topic) return <Navigate to={`/help/${ALL_TOPICS[0].id}`} replace />;
  const index = ALL_TOPICS.findIndex((t) => t.id === topic);
  if (index === -1) return <Navigate to={`/help/${ALL_TOPICS[0].id}`} replace />;
  const current = ALL_TOPICS[index];
  const previous = index > 0 ? ALL_TOPICS[index - 1] : null;
  const next = index < ALL_TOPICS.length - 1 ? ALL_TOPICS[index + 1] : null;

  return (
    <div className="pc-page d-flex" style={{ minHeight: "100%" }}>
      <nav aria-label="Help topics" className="flex-shrink-0 border-end p-3" style={{ width: 260 }}>
        <h1 className="h5 mb-3">Help</h1>
        {SECTIONS.map((section) => (
          <div key={section.title} className="mb-3">
            <div className="text-uppercase text-muted fw-semibold mb-1" style={{ fontSize: 11, letterSpacing: 0.5 }}>
              {section.title}
            </div>
            <ul className="list-unstyled mb-0">
              {section.topics.map((t) => (
                <li key={t.id}>
                  <Link
                    to={`/help/${t.id}`}
                    className={`d-block py-1 px-2 rounded text-decoration-none small ${
                      t.id === current.id ? "bg-primary-subtle fw-semibold" : ""
                    }`}
                    aria-current={t.id === current.id ? "page" : undefined}
                  >
                    {t.title}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <main className="flex-grow-1 p-4" style={{ maxWidth: 820 }}>
        <h2 className="h3 mb-1">{current.title}</h2>
        <p className="text-muted mb-4">{current.summary}</p>
        {current.body}
        <hr className="mt-5" />
        <div className="d-flex justify-content-between small">
          {previous ? <Link to={`/help/${previous.id}`}>&larr; {previous.title}</Link> : <span />}
          {next ? <Link to={`/help/${next.id}`}>{next.title} &rarr;</Link> : <span />}
        </div>
      </main>
    </div>
  );
}
