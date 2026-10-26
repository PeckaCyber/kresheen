"""The threat rule catalog: STRIDE-per-element, with a suggested mitigation
set per rule.

Which STRIDE categories apply to which element type follows the classic
STRIDE-per-element matrix (Microsoft SDL): processes get all six, data
stores get Tampering / Repudiation / Information disclosure / Denial of
service, external entities get Spoofing / Repudiation, and data flows get
Tampering / Information disclosure / Denial of service. A few *conditional*
rules layer context on top, so the output reflects the model rather than
just the element's shape:

- `crosses_boundary`: the flow joins two different trust boundaries, or
  connects an external entity to something inside the system.
- `untrusted_facing`: the component sits in a trust boundary whose label
  reads as internet/public/DMZ/third-party (labels are free text, so this is
  a keyword match, deliberately generous).

CWE/ATT&CK ids are cited inline on each rule rather than joined from the
Threat KB table, which isn't seeded yet. Rules are plain
data; adding one is adding an entry to `RULES`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from kresheen.models.threat import Methodology, ThreatElementType, ThreatOrigin, ThreatSeverity

ElementType = ThreatElementType
Condition = Literal["always", "crosses_boundary", "untrusted_facing"]


@dataclass(frozen=True)
class ThreatRule:
    id: str
    element_type: ElementType
    # A loose string, not StrideCategory: each methodology has its own
    # category set (catalog data), not a shared enum -- see models/threat.py.
    category: str | None
    title: str  # "{name}" is replaced with the element's display name
    description: str
    severity: ThreatSeverity
    mitigations: tuple[str, ...]
    methodology: Methodology = "STRIDE"
    cwe: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    condition: Condition = "always"
    # Only where the trust-boundary label contains this text (a flow matches if
    # either endpoint does). Used by user-authored rules; built-ins use `condition`.
    boundary_hint: str | None = None
    origin: ThreatOrigin = "predefined"
    # Owner-stated properties (models/element_properties.py) that must all have
    # exactly these values for the rule to fire; an unset property never matches.
    # Such a rule only ever adds a threat, it never replaces a generic one.
    when: tuple[tuple[str, bool | str], ...] = ()
    # Short phrase for the likelihood reason, e.g. "not encrypted in transit".
    asserted: str = ""


RULES: tuple[ThreatRule, ...] = (
    # -- Process: all six STRIDE categories ---------------------------------
    ThreatRule(
        id="PROC-S-01",
        element_type="process",
        category="Spoofing",
        title="Callers or peers can impersonate an identity to {name}",
        description=(
            "If {name} does not strongly authenticate whoever calls it, an attacker who can reach it "
            "can present a stolen, guessed, or forged identity and be treated as a legitimate user or "
            "service."
        ),
        severity="high",
        mitigations=(
            "Require authentication on every entry point; do not trust network location as identity.",
            "Use short-lived tokens (OIDC/JWT) or mutual TLS for service-to-service calls.",
            "Enforce MFA for human users and rotate or vault any long-lived credentials.",
        ),
        cwe=("CWE-287", "CWE-306"),
        attack=("T1078",),
    ),
    ThreatRule(
        id="PROC-T-01",
        element_type="process",
        category="Tampering",
        title="Code, configuration, or input of {name} can be tampered with",
        description=(
            "An attacker who alters {name}'s binaries, dependencies, configuration, or runtime input "
            "can change what it does. Unvalidated input is the most common route."
        ),
        severity="high",
        mitigations=(
            "Validate and canonicalize all input at the trust boundary; reject rather than sanitize where possible.",
            "Build from pinned, verified dependencies and deploy signed artifacts.",
            "Run with a read-only filesystem and keep configuration under change control.",
        ),
        cwe=("CWE-20", "CWE-494"),
        attack=("T1195", "T1565"),
    ),
    ThreatRule(
        id="PROC-R-01",
        element_type="process",
        category="Repudiation",
        title="Actions performed through {name} cannot be attributed",
        description=(
            "Without tamper-resistant, attributable logs, a user or attacker can perform actions in "
            "{name} and later deny them, and incident responders cannot reconstruct what happened."
        ),
        severity="medium",
        mitigations=(
            "Log security-relevant events (authentication, authorization decisions, data changes) with user and request identity.",
            "Ship logs off-host to append-only storage so a compromised host cannot rewrite them.",
            "Synchronize clocks and keep a retention period that matches your investigation needs.",
        ),
        cwe=("CWE-778", "CWE-117"),
        attack=("T1070",),
    ),
    ThreatRule(
        id="PROC-I-01",
        element_type="process",
        category="InformationDisclosure",
        title="{name} can leak sensitive data",
        description=(
            "{name} may expose secrets or personal data through verbose errors, logs, debug endpoints, "
            "memory, or over-broad responses."
        ),
        severity="medium",
        mitigations=(
            "Return generic errors to clients and keep stack traces server-side.",
            "Keep secrets and personal data out of logs; load secrets from a secret store, not source or environment dumps.",
            "Return only the fields a caller is authorized to see.",
        ),
        cwe=("CWE-200", "CWE-209", "CWE-532"),
        attack=("T1552",),
    ),
    ThreatRule(
        id="PROC-D-01",
        element_type="process",
        category="DenialOfService",
        title="{name} can be exhausted or crashed",
        description=(
            "Floods of requests, expensive inputs, or resource leaks can make {name} slow or "
            "unavailable to legitimate users."
        ),
        severity="medium",
        mitigations=(
            "Apply rate limits, request size limits, and timeouts at the edge and in the service.",
            "Set CPU/memory limits and autoscaling; shed load gracefully.",
            "Bound expensive operations (pagination, query complexity, regex and parser limits).",
        ),
        cwe=("CWE-400", "CWE-770"),
        attack=("T1499",),
    ),
    ThreatRule(
        id="PROC-E-01",
        element_type="process",
        category="ElevationOfPrivilege",
        title="An attacker can gain more privilege than intended through {name}",
        description=(
            "A flaw in {name}'s authorization checks, or running it with more rights than it needs, "
            "lets a low-privileged actor act as an administrator or another user."
        ),
        severity="high",
        mitigations=(
            "Enforce authorization server-side on every request (deny by default), not only in the UI.",
            "Run as an unprivileged user with the minimum IAM/RBAC permissions and dropped capabilities.",
            "Separate administrative functions and require re-authentication for them.",
        ),
        cwe=("CWE-269", "CWE-862", "CWE-863"),
        attack=("T1068",),
    ),
    ThreatRule(
        id="PROC-E-02",
        element_type="process",
        category="ElevationOfPrivilege",
        title="{name} is exposed to untrusted networks and open to injection attacks",
        description=(
            "{name} sits in an untrusted-facing trust boundary, so anyone on that network can send it "
            "crafted input. Injection (SQL, command, template, XSS) and exploitation of unpatched "
            "flaws are the typical outcome."
        ),
        severity="high",
        mitigations=(
            "Place a WAF or API gateway in front and expose only the routes that must be public.",
            "Use parameterized queries and context-aware output encoding; never build commands or queries from raw input.",
            "Patch internet-facing components on a short SLA and monitor for exploitation attempts.",
        ),
        cwe=("CWE-74", "CWE-79", "CWE-89"),
        attack=("T1190",),
        condition="untrusted_facing",
    ),
    ThreatRule(
        id="PROC-S-02",
        element_type="process",
        category="Spoofing",
        title="Sessions or credentials for {name} can be stolen or brute-forced",
        description=(
            "Because {name} is reachable from an untrusted network, attackers can attempt credential "
            "stuffing, brute force, and session or token theft against it at scale."
        ),
        severity="high",
        mitigations=(
            "Throttle and lock out repeated failed logins; add bot and credential-stuffing detection.",
            "Issue session cookies as Secure, HttpOnly, SameSite and expire/rotate them on privilege change.",
            "Offer or require MFA and check passwords against known-breached lists.",
        ),
        cwe=("CWE-307", "CWE-384", "CWE-613"),
        attack=("T1110", "T1539"),
        condition="untrusted_facing",
    ),
    # -- Data store: T, R, I, D ---------------------------------------------
    ThreatRule(
        id="STORE-T-01",
        element_type="data_store",
        category="Tampering",
        title="Data in {name} can be modified without authorization",
        description=(
            "An attacker or over-privileged service that can write to {name} can silently corrupt or "
            "alter records, including data other components trust."
        ),
        severity="high",
        mitigations=(
            "Grant write access only to the services that need it, using per-service credentials.",
            "Add integrity controls: checksums or signatures for critical records, immutable backups, and change auditing.",
            "Validate data on read as well as on write when it crosses a trust boundary.",
        ),
        cwe=("CWE-345", "CWE-284"),
        attack=("T1565",),
    ),
    ThreatRule(
        id="STORE-R-01",
        element_type="data_store",
        category="Repudiation",
        title="Access to and changes in {name} are not auditable",
        description=(
            "Without an audit trail of who read or changed data in {name}, unauthorized access and "
            "insider misuse go undetected and cannot be proven."
        ),
        severity="medium",
        mitigations=(
            "Enable database/storage audit logging for reads of sensitive data and all writes.",
            "Forward audit logs to a separate, append-only destination and alert on anomalies.",
        ),
        cwe=("CWE-778",),
        attack=("T1070",),
    ),
    ThreatRule(
        id="STORE-I-01",
        element_type="data_store",
        category="InformationDisclosure",
        title="Sensitive data in {name} can be read by unauthorized parties",
        description=(
            "Weak access control, unencrypted storage, or unprotected backups and snapshots of {name} "
            "can expose every record it holds."
        ),
        severity="high",
        mitigations=(
            "Encrypt at rest (including backups and snapshots) with managed keys, and encrypt in transit.",
            "Restrict access by least privilege; block public access and allow only known network paths.",
            "Classify the data and minimize what is stored; mask or tokenize the most sensitive fields.",
        ),
        cwe=("CWE-311", "CWE-312", "CWE-284"),
        attack=("T1530", "T1005"),
    ),
    ThreatRule(
        id="STORE-D-01",
        element_type="data_store",
        category="DenialOfService",
        title="Data in {name} can be destroyed, encrypted, or made unavailable",
        description=(
            "Deletion, ransomware, storage exhaustion, or loss of the backing service would take "
            "{name}, and everything depending on it, offline."
        ),
        severity="medium",
        mitigations=(
            "Keep tested, versioned, offline or immutable backups and define recovery time/point objectives.",
            "Set quotas and capacity alerts; separate delete permissions from write permissions.",
            "Replicate across failure domains where availability matters.",
        ),
        cwe=("CWE-400", "CWE-404"),
        attack=("T1485", "T1486"),
    ),
    ThreatRule(
        id="STORE-I-02",
        element_type="data_store",
        category="InformationDisclosure",
        title="{name} is placed in an untrusted-facing boundary",
        description=(
            "{name} is in a boundary that reads as internet-facing or public. A data store should "
            "normally be reachable only from the services that use it, so this placement makes direct "
            "attack and mass data exposure much more likely."
        ),
        severity="critical",
        mitigations=(
            "Move the store to a private network segment reachable only through the owning service.",
            "Require authentication and TLS for any remaining access and deny public ingress at the network layer.",
            "Audit for public buckets/endpoints and alert if exposure reappears.",
        ),
        cwe=("CWE-284", "CWE-668"),
        attack=("T1190", "T1530"),
        condition="untrusted_facing",
    ),
    # -- External entity: S, R ----------------------------------------------
    ThreatRule(
        id="EXT-S-01",
        element_type="external_entity",
        category="Spoofing",
        title="An attacker can impersonate {name}",
        description=(
            "The system may accept requests or data that claim to come from {name} without verifying "
            "the sender, letting an attacker act in its place."
        ),
        severity="high",
        mitigations=(
            "Authenticate the external party (mutual TLS, signed requests, or OAuth client credentials).",
            "Verify webhook/callback signatures and pin or allowlist the expected sources.",
            "Treat anything from {name} as untrusted input until validated.",
        ),
        cwe=("CWE-290", "CWE-346"),
        attack=("T1078", "T1566"),
    ),
    ThreatRule(
        id="EXT-R-01",
        element_type="external_entity",
        category="Repudiation",
        title="{name} can deny having sent or received data",
        description=(
            "If interactions with {name} are not logged with enough detail, it (or someone using its "
            "identity) can dispute a transaction and there is no evidence either way."
        ),
        severity="low",
        mitigations=(
            "Log every exchange with {name} with timestamps and request identifiers.",
            "For high-value transactions, use signed messages or receipts.",
        ),
        cwe=("CWE-778",),
        attack=("T1070",),
    ),
    ThreatRule(
        id="EXT-T-01",
        element_type="external_entity",
        category="Tampering",
        title="A compromise of {name} can feed malicious data or code into the system",
        description=(
            "{name} is outside your control. If it is breached, or is a third-party service or supplier, "
            "the data, packages, or responses it provides can carry an attack into the system."
        ),
        severity="medium",
        mitigations=(
            "Validate and constrain everything received from {name}; do not deserialize or execute it blindly.",
            "Pin and verify third-party packages and images; monitor supplier security advisories.",
            "Limit the privileges and network reach granted to integrations with {name}.",
        ),
        cwe=("CWE-829", "CWE-1357"),
        attack=("T1195",),
    ),
    # -- Data flow: T, I, D --------------------------------------------------
    ThreatRule(
        id="FLOW-T-01",
        element_type="data_flow",
        category="Tampering",
        title="Data on {name} can be modified in transit",
        description=(
            "An attacker positioned on the network path can alter messages between these components "
            "unless the channel provides integrity protection."
        ),
        severity="medium",
        mitigations=(
            "Use TLS 1.2+ (or mutual TLS) for every hop, including internal traffic.",
            "Sign messages or use authenticated encryption where the transport can't be trusted end to end.",
        ),
        cwe=("CWE-345", "CWE-319"),
        attack=("T1557",),
    ),
    ThreatRule(
        id="FLOW-I-01",
        element_type="data_flow",
        category="InformationDisclosure",
        title="Data on {name} can be intercepted",
        description=(
            "Unencrypted or weakly encrypted traffic on this flow can be read by anyone with access to "
            "the network path, exposing credentials and business data."
        ),
        severity="medium",
        mitigations=(
            "Encrypt the flow (TLS 1.2+/mTLS, or an encrypted tunnel) and disable legacy protocols and ciphers.",
            "Keep secrets out of URLs and query strings; avoid logging payloads.",
        ),
        cwe=("CWE-319", "CWE-523"),
        attack=("T1040",),
    ),
    ThreatRule(
        id="FLOW-D-01",
        element_type="data_flow",
        category="DenialOfService",
        title="The channel {name} can be flooded or disrupted",
        description=(
            "An attacker can saturate or interrupt this flow, so the components on either end cannot communicate."
        ),
        severity="low",
        mitigations=(
            "Rate-limit and apply back-pressure; use timeouts, retries with backoff, and circuit breakers.",
            "Use redundant paths or queues where the flow is critical.",
        ),
        cwe=("CWE-400",),
        attack=("T1498",),
    ),
    ThreatRule(
        id="FLOW-T-02",
        element_type="data_flow",
        category="Tampering",
        title="Untrusted data crossing a trust boundary on {name} may not be validated",
        description=(
            "This flow crosses a trust boundary, so the receiving side must not assume the data or the "
            "caller is trustworthy. Missing authentication or validation here is where most "
            "boundary-crossing attacks succeed."
        ),
        severity="high",
        mitigations=(
            "Authenticate and authorize the caller at the receiving side of the boundary.",
            "Validate schema, type, size, and range of everything that crosses; reject on failure.",
            "Do not let data from the less-trusted side choose file paths, queries, or commands.",
        ),
        cwe=("CWE-20", "CWE-306"),
        attack=("T1190",),
        condition="crosses_boundary",
    ),
    ThreatRule(
        id="FLOW-I-02",
        element_type="data_flow",
        category="InformationDisclosure",
        title="Sensitive data may leave a trust boundary on {name} unprotected",
        description=(
            "Data leaving one trust boundary for another can end up somewhere with weaker controls. "
            "Without encryption and an egress decision, sensitive fields can be exposed or over-shared."
        ),
        severity="high",
        mitigations=(
            "Send only the fields the receiver needs; redact or tokenize sensitive values before they cross.",
            "Require TLS with certificate validation (mTLS for service-to-service) across the boundary.",
            "Log and review what crosses the boundary; add egress allowlists.",
        ),
        cwe=("CWE-319", "CWE-201"),
        attack=("T1041",),
        condition="crosses_boundary",
    ),
    # -- Owner-stated properties (see engine/threats/properties.py) -----------
    ThreatRule(
        id="PROC-P-01",
        element_type="process",
        category="Spoofing",
        title="{name} does not authenticate its callers",
        description=(
            "The owner states {name} does not require callers to authenticate, so anyone who can reach "
            "it can act as a legitimate user or service."
        ),
        severity="high",
        mitigations=(
            "Require authentication on every entry point, and reject anonymous calls by default.",
            "Use mutual TLS or short-lived signed tokens for service-to-service calls.",
        ),
        cwe=("CWE-306",),
        attack=("T1078",),
        when=(("authenticates_callers", False),),
        asserted="callers are not authenticated",
    ),
    ThreatRule(
        id="PROC-P-02",
        element_type="process",
        category="ElevationOfPrivilege",
        title="{name} runs with elevated privileges",
        description=(
            "The owner states {name} runs with elevated privileges, so a flaw in it hands an attacker "
            "far more than the process needs."
        ),
        severity="high",
        mitigations=(
            "Run as an unprivileged user with the minimum capabilities the process needs.",
            "Drop root, use a read-only filesystem, and isolate it (container, sandbox, seccomp profile).",
        ),
        cwe=("CWE-250",),
        attack=("T1068",),
        when=(("runs_privileged", True),),
        asserted="runs with elevated privileges",
    ),
    ThreatRule(
        id="PROC-P-03",
        element_type="process",
        category="Tampering",
        title="Web input to {name} can inject commands or script",
        description=(
            "The owner states {name} is a web application, so untrusted browser or HTTP input reaches "
            "it: injection (SQL, command, template) and cross-site scripting are the usual result of "
            "unvalidated input."
        ),
        severity="high",
        mitigations=(
            "Use parameterized queries and safe templating; never build queries or commands from input.",
            "Encode output for its context and set a restrictive Content-Security-Policy.",
            "Validate input against an allow-list and put a WAF or gateway in front of it.",
        ),
        cwe=("CWE-89", "CWE-79"),
        attack=("T1190",),
        when=(("is_web_application", True),),
        asserted="is a web application",
    ),
    ThreatRule(
        id="STORE-P-01",
        element_type="data_store",
        category="InformationDisclosure",
        title="Data in {name} is not encrypted at rest",
        description=(
            "The owner states {name} is not encrypted at rest, so anyone who obtains the disk, a backup "
            "or a snapshot can read its contents."
        ),
        severity="high",
        mitigations=(
            "Enable encryption at rest with keys held outside the store (KMS or HSM).",
            "Encrypt backups and snapshots, and restrict who can export them.",
        ),
        cwe=("CWE-311", "CWE-312"),
        attack=("T1005",),
        when=(("is_encrypted", False),),
        asserted="not encrypted at rest",
    ),
    ThreatRule(
        id="STORE-P-02",
        element_type="data_store",
        category="InformationDisclosure",
        title="Credentials stored in {name} can be stolen",
        description=(
            "The owner states {name} stores credentials (passwords, keys or tokens). A single read of "
            "it gives an attacker working access to other systems."
        ),
        severity="critical",
        mitigations=(
            "Hash passwords with a slow, salted algorithm (argon2, bcrypt); never store them reversibly.",
            "Keep keys and tokens in a secrets manager, not in the store, and rotate them.",
            "Restrict and audit read access to this store.",
        ),
        cwe=("CWE-522", "CWE-256"),
        attack=("T1552",),
        when=(("stores_credentials", True),),
        asserted="stores credentials",
    ),
    ThreatRule(
        id="STORE-P-03",
        element_type="data_store",
        category="Tampering",
        title="Log {name} can be altered without detection",
        description=(
            "The owner states {name} is a log that is not tamper-evident. An attacker, or an insider, "
            "can edit or delete entries to hide activity, and the record can no longer be trusted."
        ),
        severity="medium",
        mitigations=(
            "Ship logs off-host to append-only or write-once storage.",
            "Sign or hash-chain entries so alteration is detectable.",
            "Separate who can write logs from who can administer them.",
        ),
        cwe=("CWE-345", "CWE-117"),
        attack=("T1070",),
        when=(("is_a_log", True), ("is_signed", False)),
        asserted="a log that is not tamper-evident",
    ),
    ThreatRule(
        id="FLOW-P-01",
        element_type="data_flow",
        category="InformationDisclosure",
        title="Traffic on {name} is not encrypted in transit",
        description=(
            "The owner states {name} is not encrypted, so anyone on the network path can read or modify "
            "what it carries (sniffing, or an adversary-in-the-middle)."
        ),
        severity="high",
        mitigations=(
            "Use TLS 1.2+ for this flow, with certificate validation on the client.",
            "Prefer mutual TLS between services and disable plaintext fallbacks.",
        ),
        cwe=("CWE-319",),
        attack=("T1040", "T1557"),
        when=(("is_encrypted", False),),
        asserted="not encrypted in transit",
    ),
    ThreatRule(
        id="FLOW-P-02",
        element_type="data_flow",
        category="Spoofing",
        title="Neither end of {name} authenticates the other",
        description=(
            "The owner states the ends of {name} do not authenticate each other, so a rogue service or "
            "client can take either side of the conversation."
        ),
        severity="high",
        mitigations=(
            "Authenticate both ends (mutual TLS, signed requests or workload identity).",
            "Do not treat network position as proof of identity.",
        ),
        cwe=("CWE-306",),
        attack=("T1557",),
        when=(("authenticated", False),),
        asserted="the ends do not authenticate each other",
    ),
)

RULES_BY_ID: dict[str, ThreatRule] = {rule.id: rule for rule in RULES}
assert len(RULES_BY_ID) == len(RULES), "duplicate threat rule id"

ASSERTED_RULES: dict[str, str] = {rule.id: rule.asserted for rule in RULES if rule.when}
"""Rule id -> the owner's stated fact, for rules that fire only on a property."""
