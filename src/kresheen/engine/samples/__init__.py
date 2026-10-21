"""Bundled sample models for first-run exploration.

Each sample is an ordinary application, not a special case: the user can edit it, re-run
it or delete it. Nothing here contains real data.

- `online_shop`: a hand-drawn model. Some facts are stated and some deliberately left
  open, so the completeness panel and the threat list show what stating facts does.
- `kubernetes`: Kubernetes manifests uploaded as a data source, so the run shows
  ingestion (namespaces as trust boundaries, flows from Service and env evidence) and
  the core's Kubernetes config checks.
- `aws`: a Terraform plan uploaded as a data source, showing the same for AWS.

The manifest and plan files sit next to this module and ship in the package.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Literal

from kresheen.engine.manual_model import ComponentSpec, FlowSpec, persist_manual_model
from kresheen.engine.provenance import input_digest
from kresheen.models.application import Application, new_application_id
from kresheen.models.asset import AssetType
from kresheen.models.data_source import DataSourceConfig, new_data_source_id
from kresheen.storage.repository import Repository

SAMPLE_NAME = "Sample: online shop"
SAMPLE_DESCRIPTION = (
    "A small example so you can see how a threat model looks. A shopper reaches a storefront, which calls an "
    "orders API backed by a database and a payment provider. Some facts are stated (the database holds card data; "
    "the orders API does not authenticate callers) and some are left open on purpose: check Model completeness. "
    "Edit it, or delete it when you are done."
)

# Stated on purpose: a classification, a web front end, an API that does not authenticate (a
# design flaw the threats should call out), and two encrypted flows. The rest stay open.
_COMPONENTS = [
    ComponentSpec("Shopper", AssetType.EXTERNAL_ENTITY, "Internet"),
    ComponentSpec("Storefront", AssetType.PROCESS, "DMZ", {"is_web_application": True}),
    ComponentSpec("Orders API", AssetType.PROCESS, "Application", {"authenticates_callers": False}),
    ComponentSpec("Orders DB", AssetType.DATA_STORE, "Data", {"data_classification": "PCI"}),
    ComponentSpec("Payment Provider", AssetType.EXTERNAL_ENTITY, "Third party"),
]
_FLOWS = [
    FlowSpec("Shopper", "Storefront", "HTTPS", {"is_encrypted": True, "protocol": "HTTPS"}),
    FlowSpec("Storefront", "Orders API", "REST"),
    FlowSpec("Orders API", "Orders DB", "SQL"),
    FlowSpec("Orders API", "Payment Provider", "card payments", {"is_encrypted": True}),
]

KUBERNETES_NAME = "Sample: Kubernetes app"
KUBERNETES_DESCRIPTION = (
    "A ticketing app on Kubernetes, built from uploaded manifests (see Data sources). Namespaces become trust "
    "boundaries and the connections come from the manifests themselves. Three weaknesses are planted on purpose: "
    "the web front end is published to the internet with no authentication, a deploy agent runs with cluster-admin "
    "rights, and a ConfigMap holds a database password. Edit it, or delete it when you are done."
)
KUBERNETES_FILE = "kubernetes_app.yaml"

AWS_NAME = "Sample: AWS app"
AWS_DESCRIPTION = (
    "A photo-sharing app on AWS, built from an uploaded Terraform plan (see Data sources). A public load balancer "
    "fronts an app server that uses a PostgreSQL database and an S3 bucket. Two weaknesses are planted on purpose: "
    "the database is publicly accessible and the bucket policy lets anyone read it. Edit it, or delete it when you "
    "are done."
)
AWS_FILE = "aws_app_plan.json"


def _new_application(name: str, description: str, owner_user_id: str) -> Application:
    now = datetime.now(UTC)
    return Application(
        id=new_application_id(),
        name=name,
        description=description,
        owner_user_id=owner_user_id,
        created_at=now,
        updated_at=now,
    )


def build_sample_application(repo: Repository, owner_user_id: str) -> Application:
    """Creates the online-shop sample: its components, connections and stated facts.
    The caller runs it. Returns the saved application."""
    application = _new_application(SAMPLE_NAME, SAMPLE_DESCRIPTION, owner_user_id)
    persist_manual_model(repo, application, owner_user_id, list(_COMPONENTS), list(_FLOWS))
    return application


def sample_file_text(filename: str) -> str:
    return files(__package__).joinpath(filename).read_text(encoding="utf-8")


def _build_uploaded(name: str, description: str, filename: str, repo: Repository, owner_user_id: str) -> Application:
    application = _new_application(name, description, owner_user_id)
    repo.save_application(application)
    data_source = DataSourceConfig(
        id=new_data_source_id(),
        application_id=application.id,
        type="manifest_upload",
        connection_details={"content": sample_file_text(filename), "filename": filename},
        created_at=datetime.now(UTC),
    )
    data_source.digest = input_digest(data_source)
    repo.save_data_source(data_source)
    return application


def build_kubernetes_sample(repo: Repository, owner_user_id: str) -> Application:
    """Creates the Kubernetes sample (an application with one manifest upload). The caller runs it."""
    return _build_uploaded(KUBERNETES_NAME, KUBERNETES_DESCRIPTION, KUBERNETES_FILE, repo, owner_user_id)


def build_aws_sample(repo: Repository, owner_user_id: str) -> Application:
    """Creates the AWS sample (an application with one Terraform plan upload). The caller runs it."""
    return _build_uploaded(AWS_NAME, AWS_DESCRIPTION, AWS_FILE, repo, owner_user_id)


SampleKey = Literal["online_shop", "kubernetes", "aws"]


@dataclass(frozen=True)
class Sample:
    key: SampleKey
    build: Callable[[Repository, str], Application]


SAMPLES: dict[str, Sample] = {
    s.key: s
    for s in (
        Sample("online_shop", build_sample_application),
        Sample("kubernetes", build_kubernetes_sample),
        Sample("aws", build_aws_sample),
    )
}
DEFAULT_SAMPLE: SampleKey = "online_shop"
