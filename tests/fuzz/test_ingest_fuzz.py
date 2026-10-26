"""Property-based fuzzing of the parsers that read untrusted input.

Each test states what must hold for any input, not for chosen examples:
- a diagram never makes the parser raise, and what it returns stays within the caps;
- a manifest or Terraform plan is either read or refused with a "bad input" error (ValueError, a YAML error),
  never a TypeError, KeyError or AttributeError from an unexpected shape, which would fail the whole run;
- values marked secret (Kubernetes Secret/ConfigMap data, Terraform `after_sensitive`) never reach the facts;
- a GitHub tarball never writes outside its extraction folder.
"""

from __future__ import annotations

import base64
import io
import json
import os
import tarfile
import time
import zlib
from pathlib import Path
from urllib.parse import quote

import yaml
from hypothesis import assume, given
from hypothesis import strategies as st

from kresheen.engine.ingest.diagrams import parse_diagram
from kresheen.engine.ingest.diagrams.model import MAX_COMPONENTS, MAX_FLOWS, MAX_NAME_CHARS
from kresheen.engine.ingest.github_repository_ingestor import _extract_tarball_safely
from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor

EXPECTED_INPUT_ERRORS = (ValueError, yaml.YAMLError, RecursionError)

# -- building blocks ----------------------------------------------------------------------------------------------

names = st.text(min_size=0, max_size=30)
scalars = st.one_of(st.none(), st.booleans(), st.integers(-(2**40), 2**40), st.floats(allow_nan=False), names)
json_values = st.recursive(
    scalars,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(names, inner, max_size=4)),
    max_leaves=20,
)


def maybe(strategy):
    """The right shape most of the time, any JSON value otherwise: wrong types are where parsers break."""
    return st.one_of(strategy, strategy, strategy, json_values)


def check_diagram(result) -> None:
    if result is None:
        return
    assert len(result.components) <= MAX_COMPONENTS
    assert len(result.flows) <= MAX_FLOWS
    keys = {c.key for c in result.components}
    for component in result.components:
        assert len(component.name) <= MAX_NAME_CHARS
        assert "\n" not in component.name
        assert component.type in ("process", "data_store", "external_entity")
    for flow in result.flows:
        assert flow.source in keys and flow.target in keys


# -- diagrams ------------------------------------------------------------------------------------------------------


@given(st.text(max_size=2000))
def test_any_text_is_safe_as_a_diagram(text):
    check_diagram(parse_diagram(text))


mermaid_lines = st.one_of(
    st.builds(
        lambda a, arrow, b, label: f"{a} {arrow}{label} {b}",
        st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,6}", fullmatch=True),
        st.sampled_from(["-->", "---", "-.->", "==>", "<-->", "--x", "--o"]),
        st.from_regex(
            r"[A-Za-z][A-Za-z0-9_]{0,6}(\[[^\]\n]{0,10}\]|\[\([^)\n]{0,10}\)\]|\(\([^)\n]{0,10}\)\))?", fullmatch=True
        ),
        st.one_of(
            st.just(""),
            st.builds(lambda t: f"|{t}|", st.text(max_size=10).filter(lambda t: "\n" not in t and "|" not in t)),
        ),
    ),
    st.builds(lambda n: f"subgraph {n}", names.filter(lambda t: "\n" not in t)),
    st.just("end"),
    st.text(max_size=40).filter(lambda t: "\n" not in t),
)


@given(st.sampled_from(["flowchart LR", "graph TD", "flowchart"]), st.lists(mermaid_lines, max_size=40))
def test_mermaid_like_input(header, lines):
    check_diagram(parse_diagram("\n".join([header, *lines])))


xml_text = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), max_size=20)
cell = st.fixed_dictionaries(
    {},
    optional={
        "id": st.one_of(st.integers(0, 8).map(str), xml_text),
        "parent": st.one_of(st.integers(0, 8).map(str), xml_text),
        "vertex": st.sampled_from(["1", "0", "x"]),
        "edge": st.sampled_from(["1", "0"]),
        "source": st.integers(0, 8).map(str),
        "target": st.integers(0, 8).map(str),
        "value": xml_text,
        "style": st.one_of(
            xml_text, st.sampled_from(["shape=cylinder3;", "shape=actor;", "swimlane;", "container=1;"])
        ),
    },
)


def _cell_xml(c: dict, geometry: tuple | None) -> str:
    from xml.sax.saxutils import quoteattr

    attrs = " ".join(f"{k}={quoteattr(v)}" for k, v in c.items())
    geo = ""
    if geometry:
        geo = '<mxGeometry x="{}" y="{}" width="{}" height="{}" as="geometry"/>'.format(*geometry)
    return f"<mxCell {attrs}>{geo}</mxCell>"


@given(
    st.lists(
        st.tuples(cell, st.one_of(st.none(), st.tuples(*[st.one_of(st.integers(-1000, 5000).map(str), xml_text)] * 4)))
    ),
    st.booleans(),
)
def test_drawio_like_input(cells, compressed):
    model = "<mxGraphModel><root>" + "".join(_cell_xml(c, g) for c, g in cells) + "</root></mxGraphModel>"
    if compressed:
        deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
        payload = base64.b64encode(deflate.compress(quote(model).encode()) + deflate.flush()).decode()
        content = f"<mxfile><diagram>{payload}</diagram></mxfile>"
    else:
        content = f"<mxfile><diagram>{model}</diagram></mxfile>"
    check_diagram(parse_diagram(content))


td_cell = st.fixed_dictionaries(
    {},
    optional={
        "id": maybe(st.integers(0, 6).map(str)),
        "shape": maybe(
            st.sampled_from(["process", "store", "actor", "flow", "trust-boundary-box", "trust-boundary-curve"])
        ),
        "data": maybe(
            st.dictionaries(
                st.sampled_from(["name", "type", "isEncrypted", "isPublicNetwork", "protocol"]), json_values
            )
        ),
        "source": maybe(st.fixed_dictionaries({"cell": st.integers(0, 6).map(str)})),
        "target": maybe(st.fixed_dictionaries({"cell": st.integers(0, 6).map(str)})),
        "position": maybe(st.fixed_dictionaries({"x": json_values, "y": json_values})),
        "size": maybe(st.fixed_dictionaries({"width": json_values, "height": json_values})),
    },
)


@given(
    st.lists(
        st.one_of(st.fixed_dictionaries({"cells": maybe(st.lists(td_cell, max_size=12))}), json_values), max_size=3
    )
)
def test_threat_dragon_like_input(diagrams):
    check_diagram(parse_diagram(json.dumps({"summary": {"title": "t"}, "detail": {"diagrams": diagrams}})))


threagile_asset = st.fixed_dictionaries(
    {},
    optional={
        "id": maybe(st.integers(0, 6).map(lambda i: f"a{i}")),
        "type": maybe(st.sampled_from(["process", "datastore", "external-entity"])),
        "encryption": maybe(st.sampled_from(["none", "transparent", "data-with-symmetric-shared-key"])),
        "internet": json_values,
        "communication_links": maybe(
            st.dictionaries(
                names,
                maybe(
                    st.fixed_dictionaries(
                        {
                            "target": maybe(st.integers(0, 6).map(lambda i: f"a{i}")),
                            "protocol": maybe(st.sampled_from(["https", "http", "jdbc"])),
                        }
                    )
                ),
                max_size=3,
            )
        ),
    },
)


@given(
    maybe(st.dictionaries(names, maybe(threagile_asset), max_size=8)),
    maybe(
        st.dictionaries(
            names,
            maybe(st.fixed_dictionaries({"technical_assets_inside": maybe(st.lists(json_values, max_size=5))})),
            max_size=3,
        )
    ),
)
def test_threagile_like_input(assets, boundaries):
    text = yaml.safe_dump({"technical_assets": assets, "trust_boundaries": boundaries})
    check_diagram(parse_diagram(text))


def test_threagile_alias_bomb_is_cheap():
    levels = ['a0: &a0 ["x","x","x","x","x","x","x","x","x"]']
    levels += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 9)]
    text = "\n".join(levels) + "\ntechnical_assets:\n  web:\n    id: *a8\n    communication_links: {l: {target: *a8}}\n"
    started = time.monotonic()
    check_diagram(parse_diagram(text))
    assert time.monotonic() - started < 2


# -- Kubernetes manifests ------------------------------------------------------------------------------------------

SECRET = "fuzz-secret-value-7f3a"

secret_keys = st.builds(
    lambda prefix, word, suffix: prefix + word + suffix,
    st.sampled_from(["", "DB_", "app.", "x-"]),
    st.sampled_from(
        [
            "password",
            "PASSWORD",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apiKey",
            "private-key",
            "access_key",
            "credentials",
        ]
    ),
    st.sampled_from(["", "_FILE", ".txt", "2"]),
)
k8s_kinds = st.sampled_from(
    [
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Pod",
        "Job",
        "CronJob",
        "ReplicaSet",
        "Service",
        "Ingress",
        "ConfigMap",
        "Secret",
        "PersistentVolumeClaim",
        "NetworkPolicy",
        "Namespace",
        "Role",
        "RoleBinding",
        "ClusterRole",
        "ServiceAccount",
        "Gateway",
        "HTTPRoute",
    ]
)
container = st.fixed_dictionaries(
    {"name": maybe(names)},
    optional={
        "image": maybe(names),
        "ports": maybe(
            st.lists(
                st.fixed_dictionaries(
                    {}, optional={"containerPort": maybe(st.integers(0, 70000)), "name": maybe(names)}
                ),
                max_size=3,
            )
        ),
        "env": maybe(
            st.lists(
                st.fixed_dictionaries(
                    {"name": maybe(names)},
                    optional={
                        "value": maybe(names),
                        "valueFrom": maybe(
                            st.fixed_dictionaries(
                                {
                                    "secretKeyRef": maybe(
                                        st.fixed_dictionaries({"name": maybe(names), "key": maybe(names)})
                                    )
                                }
                            )
                        ),
                    },
                ),
                max_size=3,
            )
        ),
        "envFrom": maybe(
            st.lists(
                st.fixed_dictionaries(
                    {},
                    optional={
                        "configMapRef": maybe(st.fixed_dictionaries({"name": maybe(names)})),
                        "secretRef": maybe(st.fixed_dictionaries({"name": maybe(names)})),
                    },
                ),
                max_size=2,
            )
        ),
        "securityContext": maybe(
            st.dictionaries(
                st.sampled_from(["privileged", "runAsNonRoot", "runAsUser", "readOnlyRootFilesystem", "capabilities"]),
                json_values,
            )
        ),
        "volumeMounts": maybe(
            st.lists(st.fixed_dictionaries({"name": maybe(names), "mountPath": maybe(names)}), max_size=2)
        ),
    },
)
pod_spec = st.fixed_dictionaries(
    {},
    optional={
        "containers": maybe(st.lists(maybe(container), max_size=3)),
        "initContainers": maybe(st.lists(maybe(container), max_size=1)),
        "hostNetwork": json_values,
        "serviceAccountName": maybe(names),
        "volumes": maybe(
            st.lists(
                st.fixed_dictionaries(
                    {"name": maybe(names)},
                    optional={
                        "secret": maybe(st.fixed_dictionaries({"secretName": maybe(names)})),
                        "configMap": maybe(st.fixed_dictionaries({"name": maybe(names)})),
                        "persistentVolumeClaim": maybe(st.fixed_dictionaries({"claimName": maybe(names)})),
                    },
                ),
                max_size=3,
            )
        ),
    },
)
spec = st.fixed_dictionaries(
    {},
    optional={
        "template": maybe(
            st.fixed_dictionaries(
                {
                    "metadata": maybe(
                        st.fixed_dictionaries({"labels": maybe(st.dictionaries(names, names, max_size=2))})
                    ),
                    "spec": maybe(pod_spec),
                }
            )
        ),
        "jobTemplate": maybe(
            st.fixed_dictionaries(
                {
                    "spec": maybe(
                        st.fixed_dictionaries({"template": maybe(st.fixed_dictionaries({"spec": maybe(pod_spec)}))})
                    )
                }
            )
        ),
        "containers": maybe(st.lists(maybe(container), max_size=2)),
        "selector": maybe(
            st.one_of(
                st.dictionaries(names, names, max_size=2),
                st.fixed_dictionaries({"matchLabels": maybe(st.dictionaries(names, names, max_size=2))}),
            )
        ),
        "ports": maybe(
            st.lists(
                st.fixed_dictionaries(
                    {}, optional={"port": maybe(st.integers(0, 70000)), "targetPort": json_values, "name": maybe(names)}
                ),
                max_size=2,
            )
        ),
        "type": maybe(st.sampled_from(["ClusterIP", "NodePort", "LoadBalancer", "ExternalName"])),
        "rules": maybe(st.lists(json_values, max_size=2)),
        "tls": json_values,
        "podSelector": json_values,
        "policyTypes": json_values,
        "ingress": json_values,
        "egress": json_values,
    },
)
k8s_record = st.fixed_dictionaries(
    {
        "apiVersion": maybe(st.sampled_from(["v1", "apps/v1", "batch/v1", "networking.k8s.io/v1"])),
        "kind": k8s_kinds,
        "metadata": maybe(
            st.fixed_dictionaries(
                {"name": maybe(names)},
                optional={
                    "namespace": maybe(names),
                    "labels": maybe(st.dictionaries(names, names, max_size=2)),
                    "annotations": maybe(st.dictionaries(names, names, max_size=2)),
                },
            )
        ),
    },
    optional={
        "spec": maybe(spec),
        # A Secret's values are never stored. A ConfigMap is ordinary config the engine reads (hosts, URLs), so only
        # values under credential-looking keys are redacted: those are the keys used here.
        "data": maybe(st.dictionaries(secret_keys, st.just(SECRET), min_size=1, max_size=3)),
        "stringData": maybe(st.dictionaries(secret_keys, st.just(SECRET), min_size=1, max_size=2)),
    },
)


def _run_manifest(raw: str):
    ingestor = ManifestUploadIngestor()
    try:
        records = ingestor.parse(raw)
        return ingestor.normalize(records, run_id="run-1", application_id="app-1")
    except EXPECTED_INPUT_ERRORS:
        return None


def _facts_text(result) -> str:
    nodes, edges = result
    return repr([(n.name, n.attributes) for n in nodes]) + repr([(e.edge_type, e.attributes) for e in edges])


@given(st.lists(k8s_record, min_size=1, max_size=6))
def test_k8s_manifests_never_crash_and_never_leak_secret_data(records):
    for record in records:  # only a ConfigMap's or Secret's data is secret; elsewhere the marker means nothing
        if record["kind"] not in ("ConfigMap", "Secret"):
            record.pop("data", None)
            record.pop("stringData", None)
    result = _run_manifest(yaml.safe_dump_all(records))
    if result is not None:
        assert SECRET not in _facts_text(result)


@given(st.text(max_size=500))
def test_any_text_as_a_manifest(text):
    _run_manifest(text)


# -- Terraform plans -----------------------------------------------------------------------------------------------

tf_types = st.sampled_from(
    [
        "aws_instance",
        "aws_db_instance",
        "aws_s3_bucket",
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_subnet",
        "aws_vpc",
        "aws_route_table",
        "aws_route",
        "aws_route_table_association",
        "aws_lb",
        "aws_iam_role",
        "aws_iam_policy",
        "aws_lambda_function",
        "aws_internet_gateway",
        "aws_rds_cluster",
        "aws_elasticache_cluster",
        "unknown_thing",
    ]
)
tf_after = st.dictionaries(
    st.sampled_from(
        [
            "name",
            "subnet_id",
            "vpc_id",
            "security_groups",
            "vpc_security_group_ids",
            "ingress",
            "egress",
            "cidr_blocks",
            "from_port",
            "to_port",
            "protocol",
            "publicly_accessible",
            "storage_encrypted",
            "user_data",
            "policy",
            "assume_role_policy",
            "route",
            "gateway_id",
            "route_table_id",
            "tags",
            "password",
            "acl",
            "internal",
            "load_balancer_type",
            "environment",
        ]
    ),
    json_values,
    max_size=8,
)


@given(
    st.lists(
        st.fixed_dictionaries(
            {
                "address": maybe(names),
                "type": maybe(tf_types),
                "name": maybe(names),
                "provider_name": maybe(names),
                "change": maybe(
                    st.fixed_dictionaries(
                        {
                            "actions": maybe(
                                st.lists(st.sampled_from(["create", "update", "delete", "no-op"]), max_size=2)
                            ),
                            "after": maybe(tf_after),
                            "after_sensitive": json_values,
                        }
                    )
                ),
            }
        ),
        min_size=1,
        max_size=6,
    ),
    json_values,
)
def test_terraform_plans_never_crash(changes, configuration):
    _run_manifest(json.dumps({"format_version": "1.2", "resource_changes": changes, "configuration": configuration}))


def _nest(path: list[str | int], leaf):
    """Value and matching after_sensitive mask with `leaf` at `path` (strings are keys, ints list positions)."""
    value, mask = leaf, True
    for step in reversed(path):
        if isinstance(step, int):
            value, mask = [None] * step + [value], [False] * step + [mask]
        else:
            value, mask = {step: value}, {step: mask}
    return value, mask


@given(
    tf_types,
    st.lists(
        st.one_of(st.sampled_from(["name", "ingress", "tags", "environment", "variables", "x"]), st.integers(0, 2)),
        min_size=1,
        max_size=10,
    ),
)
def test_terraform_sensitive_values_never_reach_the_facts(resource_type, path):
    assume(isinstance(path[0], str))
    after, mask = _nest(path, SECRET)
    plan = {
        "resource_changes": [
            {
                "address": f"{resource_type}.x",
                "type": resource_type,
                "name": "x",
                "change": {"actions": ["create"], "after": after, "after_sensitive": mask},
            }
        ]
    }
    result = _run_manifest(json.dumps(plan))
    assert result is not None
    assert SECRET not in _facts_text(result)


# -- GitHub tarballs -----------------------------------------------------------------------------------------------

member_names = st.one_of(
    st.from_regex(r"repo-abc/[a-z]{1,5}(/[a-z]{1,5}){0,2}", fullmatch=True),
    st.sampled_from(
        [
            "../evil",
            "/abs/evil",
            "repo-abc/../../evil",
            "repo-abc/./x",
            "repo-abc//x",
            "..",
            "./..",
            "repo-abc/a/../../../evil",
        ]
    ),
    st.text(alphabet="ab./\\-", min_size=1, max_size=12),
)
member_kinds = st.sampled_from(
    [tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]
)


def _tarball(members) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, kind, link in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            data = b""
            if kind == tarfile.REGTYPE:
                data = b"content"
                info.size = len(data)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = link
            tar.addfile(info, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def _escapes(root: Path, sandbox: Path) -> list[str]:
    bad = []
    for path in sandbox.rglob("*"):
        if path.is_relative_to(root):
            if path.is_symlink() and not Path(os.path.realpath(path)).is_relative_to(root.resolve()):
                bad.append(str(path))
            continue
        if path != root and not root.is_relative_to(path):
            bad.append(str(path))
    return bad


@given(st.lists(st.tuples(member_names, member_kinds, member_names), min_size=1, max_size=6))
def test_tarballs_never_write_outside_the_extraction_folder(tmp_path_factory, members):
    sandbox = tmp_path_factory.mktemp("sandbox")
    archive = sandbox / "repo.tar.gz"
    archive.write_bytes(_tarball(members))
    root = sandbox / "extract"
    root.mkdir()
    try:
        _extract_tarball_safely(str(archive), str(root))
    except (ValueError, tarfile.TarError, OSError):
        pass
    archive.unlink()
    assert _escapes(root, sandbox) == []
