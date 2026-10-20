"""A bundled sample model for first-run exploration.

It is an ordinary hand-drawn model, not a special case: the user can edit it, re-run
it or delete it. Some facts are stated and some deliberately left open, so the
completeness panel and the threat list show what stating facts does. Nothing here
contains real data.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kresheen.engine.manual_model import ComponentSpec, FlowSpec, persist_manual_model
from kresheen.models.application import Application, new_application_id
from kresheen.models.asset import AssetType
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


def build_sample_application(repo: Repository, owner_user_id: str) -> Application:
    """Creates the sample application, its components, connections and stated facts.
    The caller runs it. Returns the saved application."""
    now = datetime.now(UTC)
    application = Application(
        id=new_application_id(),
        name=SAMPLE_NAME,
        description=SAMPLE_DESCRIPTION,
        owner_user_id=owner_user_id,
        created_at=now,
        updated_at=now,
    )
    persist_manual_model(repo, application, owner_user_id, list(_COMPONENTS), list(_FLOWS))
    return application
