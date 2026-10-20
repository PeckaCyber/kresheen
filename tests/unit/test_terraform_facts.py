"""Terraform ingestion (engine/ingest/terraform_facts.py) and the sample AWS rules
(engine/threats/config_rules_aws.py), on small hand-built plans so each
behaviour is pinned on its own. Holdout case studies (kept outside this
repo) score the whole pipeline on real state; these test the parts."""

from __future__ import annotations

import base64
import json

from kresheen.engine.ingest.manifest_ingestor import ManifestUploadIngestor
from kresheen.engine.threats.config_rules import FactContext
from kresheen.engine.threats.config_rules_aws import AWS_CONFIG_RULES


def _plan(*changes: dict, configuration: dict | None = None) -> str:
    plan: dict = {"resource_changes": [{"actions": None, **c, "change": {"actions": ["create"], **c.get("change", {})}}
                                       for c in changes]}
    if configuration:
        plan["configuration"] = configuration
    return json.dumps(plan)


def _r(rtype: str, name: str, after: dict, **extra) -> dict:
    return {"address": f"{rtype}.{name}", "type": rtype, "name": name, "provider_name": "aws",
            "change": {"after": after, **extra}}


def _facts(*changes: dict, configuration: dict | None = None):
    ingestor = ManifestUploadIngestor()
    nodes, edges = ingestor.normalize(ingestor.parse(_plan(*changes, configuration=configuration)),
                                      run_id="R", application_id="A")
    return nodes, edges, {n.name: n for n in nodes}


def _hits(nodes, edges, rule_id: str):
    rule = next(r for r in AWS_CONFIG_RULES if r.id == rule_id)
    return rule.detect(FactContext(nodes, edges))


def _sg(name, ingress, sg_id="sg-1", vpc="vpc-1"):
    return _r("aws_security_group", name, {"id": sg_id, "name": name, "vpc_id": vpc, "ingress": ingress})


def _rule(port_from, port_to=None, cidr="0.0.0.0/0", protocol="tcp", description="", groups=None):
    return {"from_port": port_from, "to_port": port_to if port_to is not None else port_from, "protocol": protocol,
            "cidr_blocks": [cidr] if cidr else [], "security_groups": groups or [], "description": description}


# -- redaction -----------------------------------------------------------------------------------


def test_sensitive_values_and_credential_named_keys_are_redacted_before_storage():
    _, _, by = _facts(
        _r("aws_db_instance", "db", {"id": "db-1", "username": "admin", "password": "hunter2-real", "engine": "postgres",
                                     "master_user_secret_arn": "arn:x"},
           after_sensitive={"username": True}),
    )
    attrs = by["aws_db_instance.db"].attributes
    stored = json.dumps(attrs)
    assert "hunter2-real" not in stored
    assert attrs["config"]["username"] == "<redacted>"  # marked sensitive by Terraform
    assert attrs["config"]["password"] == "<redacted>"  # credential-named key
    assert attrs["engine"] == "postgres"


def test_user_data_is_decoded_redacted_and_flagged_without_storing_the_secret():
    script = "#!/bin/bash\nexport DB_PASSWORD=supersecret123\nyum install -y docker\n"
    _, _, by = _facts(_r("aws_instance", "web", {
        "id": "i-1", "user_data_base64": base64.b64encode(script.encode()).decode()}))
    node = by["aws_instance.web"]
    assert node.attributes["user_data_has_secrets"] is True
    assert "supersecret123" not in json.dumps(node.attributes)
    assert "yum install -y docker" in node.attributes["user_data"]
    assert "user_data_base64" not in node.attributes["config"]


def test_credentials_embedded_in_a_url_in_user_data_are_redacted_and_flagged():
    script = "git clone https://deploy:hunter2pass@git.example.com/org/repo\n"
    _, _, by = _facts(_r("aws_instance", "web", {"id": "i-1", "user_data_base64": base64.b64encode(script.encode()).decode()}))
    node = by["aws_instance.web"]
    assert node.attributes["user_data_has_secrets"] is True and "hunter2pass" not in json.dumps(node.attributes)


def test_user_data_that_fetches_a_secret_is_not_flagged_as_embedding_one():
    script = "DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id db)\nTOKEN=${var_token}\nDEBUG=false\n"
    _, _, by = _facts(_r("aws_instance", "web", {"id": "i-1", "user_data_base64": base64.b64encode(script.encode()).decode()}))
    assert "user_data_has_secrets" not in by["aws_instance.web"].attributes


def test_a_state_hash_in_user_data_is_not_mistaken_for_a_script():
    _, _, by = _facts(_r("aws_instance", "web", {"id": "i-1", "user_data": "06dd597b99ed50f2384f8b4d9ffeafeeff904b29"}))
    assert "user_data_has_secrets" not in by["aws_instance.web"].attributes


# -- diagram vs plumbing ----------------------------------------------------------------------------


def test_plumbing_resources_stay_as_facts_but_are_not_diagram_boxes():
    _, _, by = _facts(
        _r("aws_route_table", "public", {"id": "rtb-1", "vpc_id": "vpc-1"}),
        _r("random_string", "suffix", {"id": "abc"}),
        _r("aws_instance", "web", {"id": "i-1"}),
        _r("aws_efs_file_system", "cfg", {"id": "fs-1", "encrypted": False}),
    )
    assert by["aws_route_table.public"].node_type == "config_resource"
    assert by["random_string.suffix"].node_type == "config_resource"
    assert by["aws_instance.web"].node_type == "process"
    assert by["aws_efs_file_system.cfg"].node_type == "data_store"  # EFS reads as a store


# -- edges and boundaries ------------------------------------------------------------------------------


def test_internet_edge_needs_a_public_host_and_a_security_group_that_admits_the_world():
    nodes, edges, _ = _facts(
        _r("aws_vpc", "v", {"id": "vpc-1", "cidr_block": "10.0.0.0/16"}),
        _sg("web", [_rule(443), _rule(22)]),
        _sg("closed", [_rule(3306, cidr="10.0.0.0/16")], sg_id="sg-2"),
        _r("aws_instance", "public", {"id": "i-1", "associate_public_ip_address": True, "vpc_security_group_ids": ["sg-1"]}),
        _r("aws_instance", "private", {"id": "i-2", "associate_public_ip_address": False, "vpc_security_group_ids": ["sg-1"]}),
        _r("aws_instance", "shut", {"id": "i-3", "associate_public_ip_address": True, "vpc_security_group_ids": ["sg-2"]}),
    )
    targets = {by_id.name for e in edges for by_id in nodes if by_id.id == e.target_node_id}
    assert targets == {"aws_instance.public"}
    label = next(e.label for e in edges)
    assert label == "tcp/443,22"
    assert any(n.name == "Internet" and n.node_type == "external_entity" for n in nodes)


def test_a_resource_in_a_subnet_gets_that_subnet_as_a_machine_derived_boundary():
    _, _, by = _facts(
        _r("aws_vpc", "v", {"id": "vpc-1"}),
        _r("aws_subnet", "dev", {"id": "subnet-1", "vpc_id": "vpc-1"}),
        _r("aws_instance", "a", {"id": "i-1", "subnet_id": "subnet-1"}),
        _r("aws_security_group", "g", {"id": "sg-1", "vpc_id": "vpc-1", "ingress": []}),
    )
    a = by["aws_instance.a"].attributes
    assert a["trust_boundary"] == "aws_subnet.dev" and a["boundary_kind"] == "network"
    assert by["aws_security_group.g"].attributes["trust_boundary"] == "aws_vpc.v"


def test_load_balancer_reaches_target_groups_through_listeners_and_rules_nested_arns():
    nodes, edges, _ = _facts(
        _r("aws_lb", "front", {"id": "lb1", "arn": "arn:lb1", "internal": True}),
        _r("aws_lb_target_group", "app", {"id": "tg1", "arn": "arn:tg1"}),
        _r("aws_lb_target_group", "api", {"id": "tg2", "arn": "arn:tg2"}),
        _r("aws_lb_listener", "https", {"id": "l1", "arn": "arn:l1", "load_balancer_arn": "arn:lb1", "protocol": "HTTPS",
                                        "default_action": [{"type": "forward", "target_group_arn": "arn:tg1"}]}),
        _r("aws_lb_listener_rule", "api", {"id": "r1", "listener_arn": "arn:l1",
                                            "action": [{"type": "forward", "target_group_arn": "arn:tg2"}]}),
    )
    names = {n.id: n.name for n in nodes}
    assert {(names[e.source_node_id], names[e.target_node_id]) for e in edges} == {
        ("aws_lb.front", "aws_lb_target_group.app"), ("aws_lb.front", "aws_lb_target_group.api")}
    assert all(e.attributes["encrypted"] is True for e in edges)


def test_a_real_plan_resolves_unknown_ids_through_the_configuration_block():
    """A `terraform plan` leaves ids unknown, so the relationship is only in `configuration`."""
    configuration = {"root_module": {"resources": [
        {"address": "aws_instance.web", "expressions": {
            "vpc_security_group_ids": {"references": ["aws_security_group.web.id", "aws_security_group.web"]}}}]}}
    _, edges, _ = _facts(
        _sg("web", [_rule(80)], sg_id=""),  # no id in `after`, as in a plan
        _r("aws_instance", "web", {"associate_public_ip_address": True}),
        configuration=configuration,
    )
    assert len(edges) == 1 and edges[0].label == "tcp/80"


def test_security_group_ingress_from_another_group_becomes_a_flow_between_members():
    nodes, edges, _ = _facts(
        _sg("app", [], sg_id="sg-app"),
        _sg("db", [_rule(5432, cidr="", groups=["sg-app"])], sg_id="sg-db"),
        _r("aws_instance", "app", {"id": "i-1", "vpc_security_group_ids": ["sg-app"]}),
        _r("aws_db_instance", "db", {"id": "db-1", "vpc_security_group_ids": ["sg-db"]}),
    )
    names = {n.id: n.name for n in nodes}
    assert [(names[e.source_node_id], names[e.target_node_id], e.label) for e in edges] == [
        ("aws_instance.app", "aws_db_instance.db", "tcp/5432")]


def test_a_standalone_security_group_rule_is_folded_into_its_group():
    _, _, by = _facts(
        _sg("g", [], sg_id="sg-1"),
        _r("aws_security_group_rule", "ssh", {"type": "ingress", "security_group_id": "sg-1", "from_port": 22, "to_port": 22,
                                              "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}),
    )
    assert by["aws_security_group.g"].attributes["ingress_rules"][0]["from_port"] == 22


# -- AWS sample rules --------------------------------------------------------------------------------------------


def _bucket_policy(principal, bucket="quay-images", condition=None):
    statement = {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
    if condition:
        statement["Condition"] = condition
    return _r("aws_s3_bucket_policy", "p", {"bucket": bucket, "policy": json.dumps({"Statement": [statement]})})


def test_anonymous_bucket_policy_is_flagged_whatever_the_bucket_holds():
    nodes, edges, _ = _facts(_bucket_policy("*"))
    assert len(_hits(nodes, edges, "SC-AWS-T05")) == 1
    # An ML-named bucket is flagged too: a plugin's more specific rule may supersede this one.
    nodes, edges, _ = _facts(_bucket_policy("*", bucket="acme-llm-models"))
    assert len(_hits(nodes, edges, "SC-AWS-T05")) == 1


def test_named_principal_or_conditioned_bucket_policy_is_not_anonymous():
    nodes, edges, _ = _facts(_bucket_policy({"AWS": "arn:aws:iam::123456789012:role/app"}))
    assert _hits(nodes, edges, "SC-AWS-T05") == []
    nodes, edges, _ = _facts(_bucket_policy("*", condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}}))
    assert _hits(nodes, edges, "SC-AWS-T05") == []


def test_public_access_block_only_fires_when_a_flag_is_explicitly_false():
    on = {"bucket": "b", "block_public_acls": True, "block_public_policy": True, "ignore_public_acls": True,
          "restrict_public_buckets": True}
    assert _hits(*_facts(_r("aws_s3_bucket_public_access_block", "x", on))[:2], "SC-AWS-T05") == []
    off = {**on, "block_public_policy": False}
    hits = _hits(*_facts(_r("aws_s3_bucket_public_access_block", "x", off))[:2], "SC-AWS-T05")
    assert len(hits) == 1 and "block_public_policy = false" in hits[0].evidence[0]


def test_public_database_is_flagged_only_when_publicly_accessible_is_true():
    nodes, edges, _ = _facts(
        _r("aws_db_instance", "pub", {"publicly_accessible": True}),
        _r("aws_db_instance", "priv", {"publicly_accessible": False}),
    )
    assert [h.target for h in _hits(nodes, edges, "SC-AWS-T01R")] == ["aws_db_instance.pub"]


def test_kubernetes_facts_are_unaffected_by_the_aws_rules():
    from kresheen.engine.ingest.k8s_facts import build_k8s_facts

    manifest = [{"kind": "Deployment", "metadata": {"name": "web", "namespace": "prod"},
                 "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "nginx"}]}}}}]
    nodes, edges = build_k8s_facts(manifest, run_id="R", application_id="A")
    context = FactContext(nodes, edges)
    assert all(rule.detect(context) == [] for rule in AWS_CONFIG_RULES)
