# Data sources

A data source is something you give a threat model to read. A model can have several, and you can add or remove them later and re-run the model. This page says what each type reads, its limits, and what it ignores.

Kresheen only reads what the source declares. It never connects to a live cluster or cloud account. A source that cannot be read is stored and reported, never silently dropped, and the run page says so under **Incomplete** or in an amber banner. A model with few threats from such a source has not been checked. It is not a clean result.

| Type in the interface | Reads | Analysed? |
|---|---|---|
| Upload a manifest | Kubernetes YAML, or one Terraform plan (JSON) | Yes |
| GitHub repository | Kubernetes manifests in the repository, plus a dependency vulnerability scan | Yes |
| Architecture diagram | Threat Dragon JSON, draw.io, Mermaid flowchart, Threagile YAML | Yes |
| Additional documentation | Nothing | No, stored for reference only |

You can also start a model without any source: answer the guided questions, or draw it on a blank canvas.

## Manifest upload

The format is detected from the content.

### Kubernetes YAML

One or more files, each possibly holding several documents. In the web interface you can select several YAML files at once and they are joined into one source.

- **Becomes a component (a process):** Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob and Pod.
- **Becomes a data store:** Secret, ConfigMap, PersistentVolumeClaim and PersistentVolume.
- **Read as facts that shape the threats, not drawn as boxes:** Namespace (the trust boundary), Service, ServiceAccount, Role, ClusterRole, RoleBinding, ClusterRoleBinding, NetworkPolicy and Ingress.
- **Flows** are drawn only where the manifests give evidence: an internet-facing Service (LoadBalancer or NodePort) gives a flow from the internet to the workload, and a host name or URL in an environment variable or a referenced ConfigMap that names another Service gives a flow between the two. Volume mounts and config references are shown for context but are not treated as network flows.
- **Secrets are never stored.** Credential-like keys and URLs with embedded credentials are replaced with `<redacted>` before anything is saved. Only the key name is kept, so a rule can say "this ConfigMap holds credentials".
- **Misconfiguration rules** read what is declared, such as credentials in a ConfigMap, a public load balancer with no declared authentication, or a workload bound to cluster-admin. The open-source edition includes a small sample of these checks; Kresheen Pro, coming soon, adds the full set. They cannot see what the manifest does not say, so their wording is "no X is declared".
- **Ignored:** any other kind (custom resources and so on), and Helm templates that are not valid YAML until rendered. Render a chart first (`helm template`) and upload the output.
- **Limits:** a document may use at most 20 YAML aliases. Files with more are refused, because nested aliases can expand without bound. The upload as a whole is limited by `KRESHEEN_MAX_REQUEST_BYTES` (25 MiB by default).

### Terraform plan

One JSON document from `terraform show -json plan.out` (a plan with `resource_changes`) or a state exported with `terraform show -json`.

- Reads AWS-style infrastructure: instances, load balancers, databases, buckets, security groups, subnets and VPCs, and IAM users, roles and policies. Relationships come from the plan's `configuration` block, or from matching identifiers in a state.
- A resource's subnet, or else its VPC, is its trust boundary. A flow from the internet is drawn only when a resource is actually reachable (a public address or internet-facing load balancer, and a security group admitting `0.0.0.0/0`).
- Plumbing resources such as route tables, associations, key pairs and `random_*` are kept as facts but not drawn.
- **Secrets are never stored.** Values Terraform marks sensitive, and any credential-named key, are replaced with `<redacted>`. User data is decoded and passed through the same redaction.
- Resources that the plan deletes are skipped.
- **Not supported:** the relationship detection and misconfiguration rules are written for AWS (the open-source edition includes two AWS checks, a publicly accessible database and anonymous bucket access; Kresheen Pro, coming soon, adds the full set). Other providers are not specifically supported. Terraform HCL (`.tf`) files are not parsed, only the JSON from `terraform show -json`.

## GitHub repository

Give a repository URL (`https://github.com/owner/repo`), and optionally a branch, tag or commit and a token for private repositories. Kresheen downloads the repository as an archive from `api.github.com` and works on it in a temporary folder that is deleted afterwards.

- **Kubernetes manifests:** every `.yaml` and `.yml` file in the tree is checked, and files holding the Kubernetes kinds listed above become components like an uploaded manifest. This reads at most 300 files and 2,000 objects, and skips files over 1 MiB, files with more than 20 YAML aliases, templated files (containing `{{ }}`), and the folders `.git`, `node_modules`, `vendor` and `testdata`. Skips are counted and reported.
- **Dependency vulnerabilities:** [Grype](https://github.com/anchore/grype) runs on the whole tree and produces findings and a software bill of materials. Grype finds real matches only where there is a lockfile with exact versions. A bare manifest with no lockfile usually gives none. The scan is limited to 120 seconds. If Grype is missing, times out or fails, the run says so, and "no vulnerabilities" then means the dependencies were not checked.
- **Noted but not analysed:** Dockerfiles, docker-compose files, dependency manifests and lockfiles, and Terraform `.tf` files are recorded as facts about the repository. Kresheen does not parse them. Helm charts, Kustomize overlays and docker-compose files do not produce components.
- **Limits:** the archive may be at most 200 MB compressed, 500 MB unpacked and 50,000 files, with a 120 second download timeout. Archives with path traversal, absolute paths, escaping symlinks or device files are refused. The owner and repository names and the ref are validated, and the request always goes to `api.github.com`.
- **Token:** the token is optional and only needed for private repositories. It is encrypted with `KRESHEEN_SECRET_KEY` before it is stored, and no page, API response, report or export ever shows it again: the data source shows "Token saved (ends in 1234)" and lets you replace or remove the token. Saving a token fails with a clear message if the server has no `KRESHEEN_SECRET_KEY`. Deleting the data source or the application deletes the stored token. Use a fine-grained, read-only token limited to that one repository, and rotate it when people leave. A data source created by an older version that still holds a token in plain text is never shown either, and the token is encrypted the next time the source is listed or run with `KRESHEEN_SECRET_KEY` set.
- **CI:** `kresheen ci --ref SHA` scans a specific commit without changing the saved source. See [ci-integration.md](ci-integration.md).

## Architecture diagram

The format is detected from the content, not the file name. Components, flows and trust boundaries become part of the model. Facts the file states are carried over as stated properties, which you can change later. Threats already listed in a file are **not** imported. They are worked out again from the model.

| Format | Read as |
|---|---|
| **OWASP Threat Dragon** JSON (v2 and the older layout) | Actors, processes and stores. A trust-boundary box holds the elements whose centre lies inside it. Ticked properties are carried over: encrypted, stores credentials, is a log, is signed, is a web application, and for flows encrypted and crosses a public network. Boundary curves and text blocks are ignored. |
| **draw.io / diagrams.net** (`.drawio`, `.xml`, plain or compressed) | Shapes become components: cylinders and database shapes are data stores, actor and user shapes are external entities, everything else a process. Edges with both ends on a component become flows. A swimlane, container or dashed rectangle that contains other shapes is a trust boundary. Free text, unlabelled images and dangling edges are ignored. |
| **Mermaid** flowchart (`flowchart` or `graph`) | `A[Web] -->\|HTTPS\| B[(Database)]` gives two components and a flow. A cylinder is a data store, a circle an external entity, anything else a process. A `subgraph` is a trust boundary. Styling, click and class lines are ignored, and a line that cannot be read is skipped. |
| **Threagile** model (YAML with `technical_assets`) | External entities, processes and data stores, `communication_links` as flows, `trust_boundaries` as zones. Encryption and authentication stated in the file are carried over. Threagile's own risks and rules are not imported. |

- **Limits:** a diagram file may be up to 5 MB, and a model keeps at most 500 components and 2,000 flows (Mermaid also stops at 5,000 lines of up to 2,000 characters). If a file is larger, only the first part is read and the run page says so.
- **XML safety:** draw.io files that declare a `DOCTYPE` or entities are refused, and compressed pages are inflated with a hard size cap (10 MB).
- **Not read:** images, PDFs, Visio files, prose, and any other format. They are stored and shown as "not read". If a diagram names a component that matches nothing in your other infrastructure sources, the threats view lists it as possible documentation drift (matching is by exact name, ignoring case).

## Additional documentation

A text or Markdown file attached to a model. It is stored as a reference only. The rule-based engine does not read documents, so nothing in the file affects the threats, and the run page says so. Describe the system, add components by hand, or upload a manifest or diagram instead.

## After a run

- The run page lists each source with its status: analysed, stored for reference only, or empty (read, but no components found).
- **Stale** means a source's content changed since the last run, or a source was added or removed, or the model never ran. Re-run it, and **What changed since the last run** shows the difference.
