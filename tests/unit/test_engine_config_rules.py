import json

from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from kresheen.engine.threats.config_rules import (
    CONFIG_RULES,
    CONFIG_RULES_BY_ID,
    FactContext,
    authenticating_workload_names,
)


def _hits(rule_id: str, manifest: str) -> dict[str, list[str]]:
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R", application_id="A", connection_details={"content": manifest}
    )
    return {h.target: h.evidence for h in CONFIG_RULES_BY_ID[rule_id].detect(FactContext(nodes, edges))}


def _deployment(name, ns="n", image="app:1", labels=None, extra_spec="", container_extra=""):
    labels = labels or {"app": name}
    label_yaml = ", ".join(f"{k}: {v}" for k, v in labels.items())
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: {ns}}}
spec:
  template:
    metadata: {{labels: {{{label_yaml}}}}}
    spec:
{extra_spec}
      containers:
      - name: c
        image: {image}
{container_extra}
---"""


def _service(name, ns="n", type_="ClusterIP", ports="[{name: http, port: 80}]", selector=None):
    selector = selector or {"app": name}
    sel = ", ".join(f"{k}: {v}" for k, v in selector.items())
    return f"""
apiVersion: v1
kind: Service
metadata: {{name: {name}, namespace: {ns}}}
spec: {{type: {type_}, selector: {{{sel}}}, ports: {ports}}}
---"""


def _configmap(name, data, ns="n"):
    body = "\n".join(f"  {k}: {json.dumps(v)}" for k, v in data.items())
    return f"""
apiVersion: v1
kind: ConfigMap
metadata: {{name: {name}, namespace: {ns}}}
data:
{body}
---"""


def test_every_config_rule_is_tagged_and_documented():
    assert len({r.id for r in CONFIG_RULES}) == len(CONFIG_RULES)
    for rule in CONFIG_RULES:
        assert rule.taxonomy_id.startswith("T") and rule.mitigations and rule.applies_when and rule.cwe


def test_t01_flags_an_exposed_workload_without_auth_and_respects_declared_auth():
    exposed = _deployment("web") + _service("web", type_="LoadBalancer")
    assert "Deployment/web" in _hits("SC-T01", exposed)
    assert _hits("SC-T01", _deployment("web") + _service("web")) == {}  # ClusterIP is not exposed
    declared = (
        _deployment("web", container_extra="        envFrom: [{configMapRef: {name: web-cfg}}]")
        + _service("web", type_="LoadBalancer")
        + _configmap("web-cfg", {"OIDC_ISSUER": "https://sso"})
    )
    assert _hits("SC-T01", declared) == {}


def test_t01_treats_disable_auth_true_as_authentication_off_not_on():
    manifest = _deployment("llm", container_extra='        env: [{name: DISABLE_AUTH, value: "true"}]') + _service(
        "llm", type_="NodePort"
    )
    assert "Deployment/llm" in _hits("SC-T01", manifest)
    enabled = _deployment("llm", container_extra='        env: [{name: DISABLE_AUTH, value: "false"}]') + _service(
        "llm", type_="NodePort"
    )
    assert _hits("SC-T01", enabled) == {}


def test_t01_sees_an_ingress_and_an_auth_annotation_on_it_suppresses():
    ingress = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: i, namespace: n%s}
spec:
  rules: [{http: {paths: [{backend: {service: {name: web}}}]}}]
---"""
    base = _deployment("web") + _service("web")
    assert "Deployment/web" in _hits("SC-T01", base + ingress % "")
    guarded = ingress % ", annotations: {nginx.ingress.kubernetes.io/auth-url: 'https://sso'}"
    assert _hits("SC-T01", base + guarded) == {}


def test_authenticating_workload_names_reflects_declared_auth_not_exposure():
    declared = (
        _deployment("web", container_extra="        envFrom: [{configMapRef: {name: web-cfg}}]")
        + _service("web", type_="LoadBalancer")
        + _configmap("web-cfg", {"OIDC_ISSUER": "https://sso"})
    )
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R", application_id="A", connection_details={"content": declared}
    )
    assert authenticating_workload_names(FactContext(nodes, edges)) == {"Deployment/web"}

    # Not exposed and no auth declared either: absence, not a false "no auth".
    quiet = _deployment("internal-only")
    nodes, edges = ManifestUploadIngestor().run(run_id="R", application_id="A", connection_details={"content": quiet})
    assert authenticating_workload_names(FactContext(nodes, edges)) == set()


def test_t02_only_for_cluster_admin_bound_to_a_serviceaccount_a_workload_uses():
    binding = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: b}
roleRef: {kind: ClusterRole, name: %s}
subjects: [{kind: ServiceAccount, name: ci, namespace: n}]
---"""
    used = _deployment("jenkins", extra_spec="      serviceAccountName: ci")
    assert "Deployment/jenkins" in _hits("SC-T02", used + binding % "cluster-admin")
    assert _hits("SC-T02", used + binding % "view") == {}
    assert _hits("SC-T02", _deployment("jenkins") + binding % "cluster-admin") == {}  # nobody runs as that SA


def test_t08_flags_credentials_in_configmaps_and_never_in_secrets():
    cm = _configmap("creds", {"db-password": "x", "LOG": "info"})
    assert "ConfigMap/creds" in _hits("SC-T08", cm)
    assert _hits("SC-T08", _configmap("plain", {"LOG": "info"})) == {}
    secret = "apiVersion: v1\nkind: Secret\nmetadata: {name: s, namespace: n}\nstringData: {password: x}\n---"
    assert _hits("SC-T08", secret) == {}
    connstring = _configmap("db", {"config.yaml": "connstring: host=db user=u password=hunter2 sslmode=disable"})
    assert "ConfigMap/db" in _hits("SC-T08", connstring)


def test_non_kubernetes_facts_are_ignored_by_every_rule():
    """Terraform and GitHub runs also produce process/data_store facts,
    with none of the Kubernetes attributes. The rules must skip them, not crash."""
    from datetime import UTC, datetime

    from kresheen.models.facts import FactNode

    def fact(node_type, name, **attributes):
        return FactNode(
            id=f"N-{name}",
            run_id="R",
            application_id="A",
            node_type=node_type,
            name=name,
            attributes=attributes,
            source_ref="manifest_upload:terraform",
            discovered_at=datetime.now(UTC),
        )

    nodes = [
        fact("process", "aws_instance.web", resource_type="aws_instance", provider="aws"),
        fact("data_store", "aws_s3_bucket.data", resource_type="aws_s3_bucket"),
        fact("external_entity", "org/repo"),
        fact("code_artifact", "go.sum"),
    ]
    context = FactContext(nodes, [])

    for rule in CONFIG_RULES:
        assert rule.detect(context) == [], rule.id


def test_core_ships_exactly_the_sample_rules():
    """The core keeps a small set of sample rules; the rest of the catalogue is a plugin's (`Plugin.config_rules`).
    Changing this set is deliberate, so it fails here first."""
    assert {r.id for r in CONFIG_RULES} == {"SC-T01", "SC-T02", "SC-T08", "SC-AWS-T01R", "SC-AWS-T05"}
    assert set(CONFIG_RULES_BY_ID) == {r.id for r in CONFIG_RULES}
