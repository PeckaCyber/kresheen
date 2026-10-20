"""Coverage invariant:
engine/threats/coverage.py."""

from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from kresheen.engine.threats.coverage import check_coverage


def _gaps(manifest: str):
    nodes, edges = ManifestUploadIngestor().run(run_id="R", application_id="A", connection_details={"content": manifest})
    return check_coverage(nodes, edges)


def _deployment(name, ns="n", sa=None):
    sa_line = f"      serviceAccountName: {sa}\n" if sa else ""
    return f"""
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {name}, namespace: {ns}}}
spec:
  template:
    metadata: {{labels: {{app: {name}}}}}
    spec:
{sa_line}      containers:
      - name: c
        image: app:1
---"""


def _service(name, ns="n", selector=None):
    selector = selector or {"app": name}
    sel = ", ".join(f"{k}: {v}" for k, v in selector.items())
    return f"""
apiVersion: v1
kind: Service
metadata: {{name: {name}, namespace: {ns}}}
spec: {{type: ClusterIP, selector: {{{sel}}}, ports: [{{name: http, port: 80}}]}}
---"""


def _ingress(name, ns="n", backend="web"):
    return f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {{name: {name}, namespace: {ns}}}
spec:
  rules: [{{http: {{paths: [{{backend: {{service: {{name: {backend}}}}}}}]}}}}]
---"""


def _role_binding(name, role, subjects_yaml, ns="n"):
    return f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {{name: {name}, namespace: {ns}}}
roleRef: {{kind: Role, name: {role}}}
subjects: {subjects_yaml}
---"""


def test_no_facts_no_gaps():
    assert check_coverage([], []) == []


def test_ingress_with_real_backend_and_matching_workload_is_no_gap():
    manifest = _deployment("web") + _service("web") + _ingress("i", backend="web")
    assert _gaps(manifest) == []


def test_ingress_naming_an_unknown_backend_service_is_a_gap():
    manifest = _deployment("web") + _service("web") + _ingress("i", backend="does-not-exist")
    gaps = _gaps(manifest)
    assert len(gaps) == 1
    assert gaps[0].kind == "ingress" and "does-not-exist" in gaps[0].reason


def test_ingress_whose_service_matches_no_workload_is_a_gap():
    manifest = _service("orphan", selector={"app": "nobody"}) + _ingress("i", backend="orphan")
    gaps = _gaps(manifest)
    assert len(gaps) == 1
    assert gaps[0].kind == "ingress" and "matches no workload" in gaps[0].reason


def test_binding_to_a_serviceaccount_a_workload_uses_is_no_gap():
    manifest = _deployment("app", sa="app-sa") + _role_binding(
        "b", "edit", "[{kind: ServiceAccount, name: app-sa, namespace: n}]"
    )
    assert _gaps(manifest) == []


def test_binding_to_an_unused_serviceaccount_is_a_gap():
    manifest = _deployment("app", sa="app-sa") + _role_binding(
        "b", "edit", "[{kind: ServiceAccount, name: someone-else, namespace: n}]"
    )
    gaps = _gaps(manifest)
    assert len(gaps) == 1
    assert gaps[0].kind == "rbac_binding" and "someone-else" in gaps[0].reason


def test_binding_to_a_non_serviceaccount_subject_is_a_gap():
    manifest = _deployment("app") + _role_binding("b", "edit", "[{kind: User, name: alice}]")
    gaps = _gaps(manifest)
    assert len(gaps) == 1
    assert gaps[0].kind == "rbac_binding" and "User" in gaps[0].reason


def test_binding_with_no_subjects_is_a_gap():
    manifest = _deployment("app") + _role_binding("b", "edit", "[]")
    gaps = _gaps(manifest)
    assert len(gaps) == 1
    assert "no subjects" in gaps[0].reason
