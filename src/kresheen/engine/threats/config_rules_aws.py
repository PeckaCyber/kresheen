"""Sample configuration-aware rules for AWS infrastructure described in Terraform.

Same contract as config_rules.py (each rule instantiates a taxonomy threat and
cites the exact resources and attributes as evidence), but reading the facts
engine/ingest/terraform_facts.py produces: normalized security-group ingress
rules, IAM/bucket policy statements, and a handful of resolved relationships.

Every claim is about *declared* configuration: "the policy allows Principal *".
These rules cannot see a WAF, an SCP, a resource policy outside the plan, or
application-level authentication, and they say so in the evidence wording.
"""

from __future__ import annotations

import re

from kresheen.engine.threats.config_rules import ConfigRule, FactContext, Hit
from kresheen.models.facts import FactNode

_ML_TOKENS = frozenset({"model", "models", "llm", "ml", "mlflow", "inference", "ai"})


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokens(*values: object) -> set[str]:
    return {t for v in values for t in _TOKEN_RE.findall(str(v).lower())}


def config_of(node: FactNode) -> dict:
    config = node.attributes.get("config")
    return config if isinstance(config, dict) else {}


def _detect_public_database(ctx: FactContext) -> list[Hit]:
    return [
        Hit("component", db.name, ["publicly_accessible = true"])
        for db in ctx.tf("aws_db_instance", "aws_rds_cluster_instance")
        if config_of(db).get("publicly_accessible") is True
    ]


def _bucket_of(node: FactNode) -> str:
    return str(node.attributes.get("bucket") or node.attributes.get("id") or node.name)


def _is_ml_bucket(node: FactNode, ctx: FactContext) -> bool:
    tags: list[object] = []
    for bucket in ctx.tf("aws_s3_bucket"):
        if _bucket_of(bucket) == _bucket_of(node) and isinstance(config_of(bucket).get("tags"), dict):
            tags.extend(config_of(bucket)["tags"].values())
    return bool(tokens(_bucket_of(node), node.name, *tags) & _ML_TOKENS)


def public_bucket_hits(ctx: FactContext, *, ml: bool | None = None) -> list[Hit]:
    """Buckets open to anonymous access. `ml` limits them to (True) or excludes (False) ML/model storage."""
    hits = []
    for policy in ctx.tf("aws_s3_bucket_policy"):
        anonymous = [
            st
            for st in policy.attributes.get("policy_statements", [])
            if st["effect"] == "Allow"
            and "*" in st["principals"]
            and not st["has_condition"]
            and any(a == "*" or a.lower().startswith("s3:") for a in st["actions"])
        ]
        if anonymous and (ml is None or _is_ml_bucket(policy, ctx) == ml):
            actions = sorted({a for st in anonymous for a in st["actions"]})
            hits.append(Hit("component", policy.name, [f"bucket policy allows Principal * to {', '.join(actions)}"]))
    for block in ctx.tf("aws_s3_bucket_public_access_block"):
        cfg = config_of(block)
        off = [
            f
            for f in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
            if cfg.get(f) is False
        ]
        if off and (ml is None or _is_ml_bucket(block, ctx) == ml):
            hits.append(
                Hit(
                    "component",
                    block.name,
                    [f"public access is not blocked ({', '.join(f'{f} = false' for f in off)})"],
                )
            )
    for bucket in ctx.tf("aws_s3_bucket"):
        if str(config_of(bucket).get("acl", "")).startswith("public-read") and (
            ml is None or _is_ml_bucket(bucket, ctx) == ml
        ):
            hits.append(Hit("component", bucket.name, [f"acl = {config_of(bucket)['acl']}"]))
    return hits


def _detect_public_bucket(ctx: FactContext) -> list[Hit]:
    return public_bucket_hits(ctx)


AWS_CONFIG_RULES: tuple[ConfigRule, ...] = (
    ConfigRule(
        "SC-AWS-T01R",
        "T01",
        "data_store",
        "Spoofing",
        "Database {name} is publicly accessible",
        "publicly_accessible is true, so the database endpoint resolves to a public address and depends only on its security group and credentials.",
        "high",
        (
            "Set publicly_accessible = false and place the database in a private subnet.",
            "Reach it through the application tier, a bastion or a VPN.",
        ),
        ("CWE-306",),
        ("T1190",),
        "An RDS instance sets publicly_accessible = true",
        _detect_public_database,
    ),
    ConfigRule(
        "SC-AWS-T05",
        "T05",
        "data_store",
        "Spoofing",
        "{name} allows anonymous access to a bucket",
        "The bucket's policy grants access to Principal * or its public-access block is switched off, so anyone on the internet may be able to read (and possibly list) its contents without authenticating.",
        "high",
        (
            "Enable all four S3 Block Public Access settings on the bucket and the account.",
            "Remove Principal * statements; serve public content through CloudFront with origin access control.",
            "Grant access to named principals only.",
        ),
        ("CWE-732", "CWE-284"),
        ("T1530",),
        "A bucket policy allows Principal *, a public-access block has a flag false, or a bucket ACL is public-read",
        _detect_public_bucket,
    ),
)
