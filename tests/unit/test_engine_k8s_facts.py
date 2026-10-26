import json

from kresheen.engine.ingest.k8s_facts import port_is_plaintext, redact_value
from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor


def _facts(manifest: str):
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R", application_id="A", connection_details={"content": manifest}
    )
    return {n.name: n for n in nodes}, edges


def _edge_labels(nodes, edges, edge_type=None):
    by_id = {n.id: n.name for n in nodes.values()}
    return {
        (by_id[e.source_node_id], by_id[e.target_node_id], e.label) for e in edges if edge_type in (None, e.edge_type)
    }


def test_redaction_hides_credential_values_and_reports_that_they_were_there():
    assert redact_value("admin-password", "hunter2") == ("<redacted>", True)
    assert redact_value("DATABASE_URL", "postgresql://u:s3cret@db:5432/x") == (
        "postgresql://u:<redacted>@db:5432/x",
        True,
    )
    safe, credential = redact_value("config", "host=db user=u password=s3cret sslmode=disable")
    assert credential and "s3cret" not in safe and "sslmode=disable" in safe
    safe, credential = redact_value("app.ini", "[x]\nSECRET_KEY = abc123\nMODE = prod")
    assert credential and "abc123" not in safe and "MODE = prod" in safe
    assert redact_value("LOG_LEVEL", "debug") == ("debug", False)


def test_configmap_keeps_key_names_but_no_credential_values_in_the_stored_fact():
    nodes, _ = _facts("""
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: prod}
data:
  admin-password: "hunter2"
  url: "postgresql://u:s3cret@db:5432/x"
  LOG_LEVEL: debug
""")
    cfg = nodes["ConfigMap/cfg"]
    assert sorted(cfg.attributes["secret_keys"]) == ["admin-password", "url"]
    assert cfg.attributes["data"]["LOG_LEVEL"] == "debug"
    dumped = json.dumps(cfg.model_dump(mode="json"))
    assert "hunter2" not in dumped and "s3cret" not in dumped


def test_kinds_map_to_diagram_elements_or_metadata_and_namespace_is_the_trust_boundary():
    nodes, _ = _facts("""
apiVersion: v1
kind: Namespace
metadata: {name: prod-zone}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod-zone}
spec:
  template:
    spec:
      containers: [{name: web, image: "web:1"}]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: prod-zone}
spec: {selector: {app: web}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rb, namespace: prod-zone}
roleRef: {kind: ClusterRole, name: edit}
subjects: [{kind: ServiceAccount, name: ci, namespace: ci-zone}]
""")
    assert nodes["Deployment/web"].node_type == "process"
    assert nodes["Deployment/web"].attributes["trust_boundary"] == "prod-zone"
    assert nodes["Namespace/prod-zone"].node_type == "namespace"
    assert nodes["Service/web"].node_type == "service"
    assert nodes["RoleBinding/rb"].node_type == "rbac_binding"
    assert nodes["RoleBinding/rb"].attributes["binding_namespace"] == "prod-zone"
    assert nodes["RoleBinding/rb"].attributes["subjects"][0]["namespace"] == "ci-zone"


def test_service_selects_pods_by_template_labels_within_its_namespace_only():
    nodes, edges = ManifestUploadIngestor().run(
        run_id="R",
        application_id="A",
        connection_details={
            "content": """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: a}
spec:
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: b}
spec:
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: a}
spec: {selector: {app: web}}
"""
        },
    )
    routes = [e for e in edges if e.edge_type == "routes_to"]
    assert len(routes) == 1
    target = next(n for n in nodes if n.id == routes[0].target_node_id)
    assert target.attributes["namespace"] == "a"


def test_loadbalancer_and_ingress_publish_a_workload_to_an_internet_element():
    nodes, edges = _facts("""
apiVersion: apps/v1
kind: Deployment
metadata: {name: a, namespace: n}
spec:
  template:
    metadata: {labels: {app: a}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: v1
kind: Service
metadata: {name: a, namespace: n}
spec: {type: LoadBalancer, selector: {app: a}, ports: [{name: http, port: 80}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: b, namespace: n}
spec:
  template:
    metadata: {labels: {app: b}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: v1
kind: Service
metadata: {name: b, namespace: n}
spec: {selector: {app: b}, ports: [{name: http, port: 80}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: b-ing, namespace: n}
spec:
  rules: [{http: {paths: [{backend: {service: {name: b}}}]}}]
""")
    assert nodes["Internet"].node_type == "external_entity"
    assert nodes["Internet"].attributes["trust_boundary"] == "internet"
    flows = {(s, t): e for s, t, e in _edge_labels(nodes, edges, "data_flow")}
    assert ("Internet", "Deployment/a") in flows and ("Internet", "Deployment/b") in flows
    ingress_edge = next(e for e in edges if e.edge_type == "data_flow" and e.target_node_id == nodes["Deployment/b"].id)
    assert ingress_edge.attributes["encrypted"] is False  # no TLS block on the Ingress


def test_urls_in_env_and_referenced_configmaps_become_flows_with_known_encryption():
    nodes, edges = _facts("""
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: n}
data: {API_URL: "https://api.n.svc.cluster.local:8443", DB: "postgresql://u:pw@db:5432/x"}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: client, namespace: n}
spec:
  template:
    metadata: {labels: {app: client}}
    spec:
      containers:
      - name: c
        image: i
        env:
        - {name: PLAIN, value: "http://api.n.svc.cluster.local:8080"}
        - name: DB
          valueFrom: {configMapKeyRef: {name: cfg, key: DB}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: n}
spec:
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: n}
spec: {selector: {app: api}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: db, namespace: n}
spec:
  template:
    metadata: {labels: {app: db}}
    spec: {containers: [{name: c, image: i}]}
---
apiVersion: v1
kind: Service
metadata: {name: db, namespace: n}
spec: {selector: {app: db}}
""")
    by_target = {}
    for e in edges:
        if e.edge_type == "data_flow":
            by_target[next(n.name for n in nodes.values() if n.id == e.target_node_id)] = e
    assert (
        by_target["Deployment/api"].attributes["encrypted"] is False
    )  # first reference seen is the plain http env var
    assert by_target["Deployment/db"].attributes["encrypted"] is False  # postgresql:// with no sslmode
    labels = _edge_labels(nodes, edges)
    assert ("ConfigMap/cfg", "Deployment/client", "config") in labels


def test_port_encryption_is_conservative_about_unknowns():
    assert port_is_plaintext("http", 80) is True
    assert port_is_plaintext("https", 443) is False
    assert port_is_plaintext(None, 5432) is True
    assert port_is_plaintext("grpc", 50051) is None
    assert port_is_plaintext("ssh", 22) is None


def test_manifest_with_a_wrongly_typed_field_is_refused_with_a_clear_error():
    import pytest

    # Found by tests/fuzz: a list where a mapping belongs crashed the run with an AttributeError.
    ingestor = ManifestUploadIngestor()
    raw = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web}\nspec: {template: {spec: {containers: 5}}}\n"
    with pytest.raises(ValueError, match="Deployment/web document has a field of an unexpected type"):
        ingestor.normalize(ingestor.parse(raw), run_id="R", application_id="A")
