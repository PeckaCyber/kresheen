# AI assist (experimental)

Kresheen has an optional AI assist. It is experimental, it is off by default, and it uses your own Anthropic API key.

**Rule-based analysis does not need AI.** The threats, risk scores, action plan and reports come from built-in rules and are the same with AI assist on or off. AI assist never changes them.

## What it can do

There are two features, and both only appear when AI assist is available to you.

**Describe your system (guided setup).** You paste a description or upload a `.txt` or `.md` file. AI suggests answers to the guided setup questions. Each suggested answer is marked, and **nothing is created** until you review the form and submit it yourself. The model never writes components, flows or threats.

**Explain a threat.** On a threat, the **Explain** button gives a plain-language explanation of what it means for that component, why it matters, and what the listed mitigation does. The text is shown on screen. It is not saved and is not added to reports.

## Turning it on and off

AI assist needs two switches, both off by default.

1. **The owner turns it on for the installation** in **Settings**, in the **AI assist** card, with the "Turn on AI assist for this instance" switch.
2. **Each person who wants it adds their own Anthropic API key** in the same card, reads the notice, tests the key and picks a model from the list their key can use. A person without a key sees no AI buttons. An organisation-level key that is not tied to one workspace also needs the workspace ID (from the Anthropic Console, under Workspaces), which Kresheen sends as the `anthropic-workspace-id` header; a key created inside a workspace does not.

If either switch is off, no AI buttons appear, the AI endpoints answer "not found", and nothing is sent anywhere. Turning the instance switch off keeps stored keys. Each person can remove their own key at any time, which also removes their model choice.

**Forcing it off.** An administrator can set the environment variable `KRESHEEN_AI_DISABLED=1` (also `true`, `yes` or `on`). This wins over the owner's setting, and the switch in Settings shows as locked. Use it if policy says no data may go to an AI provider. The Helm chart and the Compose file leave it unset. See [configuration.md](configuration.md).

For a default install, Kresheen makes no requests to Anthropic.

## What is sent to Anthropic

Only the text for the feature you use, sent with your key to Anthropic's API.

| Feature | What is sent |
|---|---|
| Describe your system | The description or file text you provided, up to 20,000 characters. |
| Explain a threat | The threat's title, methodology, category, severity, rule id, description, why it applies and mitigations, the affected component's name and type, and the properties stated for that component. |

Nothing else from your models is sent: no other components, no data sources, no findings, no reports, and no other users' data.

Before sending:

- Values that look like credentials (passwords, tokens, API keys, private keys, URLs with credentials) are replaced with `<redacted>`.
- Invisible and control characters used to hide instructions are removed.
- **Component details always fit.** Stated property values are limited to 500 characters when you enter them (names and protocols read from imported diagrams to 200), so an Explain request stays well under its 16,000-character limit. As a backstop, a longer value would be cut to 1,000 characters and the explanation would say it was based on shortened details.
- Text over the size limit is refused, not cut.

How Anthropic handles API data is set by Anthropic's terms, which can change. Read the current terms before turning this on:

- [Anthropic API data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
- [Anthropic privacy center](https://privacy.claude.com/en/articles/7996866)
- [Anthropic legal terms and policies](https://www.anthropic.com/legal)

## Keys

Keys belong to the person who adds them, not to the installation. A key is encrypted with `KRESHEEN_SECRET_KEY` before it is stored, is never shown again, and is decrypted only for the moment of a request made by its owner. If `KRESHEEN_SECRET_KEY` is not set, the app refuses to store a key and says so. If you lose or change that secret key, stored keys cannot be read and people must add them again.

## Safeguards

Text you send is written by whoever owns the system under review, so it is handled as data and never as instructions:

- **Fixed instructions, tagged data.** The instructions are fixed in the code. Your text goes into a separate tagged block with a random id on every request, and anything in it that imitates the tag is neutralised. The model is told that the block is data to analyse, whatever it claims.
- **Checked before sending.** The text is scanned for wording aimed at automated tools: "ignore previous instructions", addressing the model, asking it to reveal its instructions, fake role or delimiter markers, and hidden characters. A match shows you a warning and is recorded in the audit log. A match is a signal, not proof: a security write-up about prompt injection will match too.
- **Answers are strictly checked.** For the guided setup the answer must be form answers from the allowed options. For Explain it must be a bounded piece of text. Anything else is rejected.
- **AI can only add, never remove.** The answers have nowhere to write to threats, findings or your model. AI cannot remove or downgrade a threat.
- **Limits.** Each request is tried once and times out after 60 seconds (it is not retried automatically; you see a message and can try again). Answers are capped at 2,000 tokens. Each person is limited to 20 AI requests per 10 minutes, counted per person, not per installation. The limit is kept in memory for each server process, so it resets when the server restarts.
- **Audit.** Every AI request is recorded: who, which feature, which model, token counts and the outcome. The audit log never holds your text, the answers or any key. Adding or removing a key, and turning AI assist on or off, are recorded as security events.

AI output can be wrong. Review it before relying on it.

## For testing only

`KRESHEEN_AI_BASE_URL` points the Anthropic client at another server, such as a stub used in automated tests. It exists for testing, can only be set in the environment, and must not be set in a real deployment. See [configuration.md](configuration.md).
