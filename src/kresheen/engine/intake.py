"""Guided intake: a few plain questions become a starter threat model.

The answers become an ordinary hand-drawn model: components, connections and stated
facts (data classification, authentication, AI/ML). Nothing about threats is decided
here; threats, ranking, completeness and the action plan are computed from the model
exactly as for any other, so the only thing this does is save the user from drawing
the obvious parts and from having to know which facts to state. It is deterministic and
needs no LLM.

Options and their labels live here, once, and are served to the UI
(`GET /api/intake/options`) so the form and this generator cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from kresheen.engine.manual_model import ComponentSpec, FlowSpec, persist_manual_model
from kresheen.engine.threats.properties import known_property_keys
from kresheen.models.application import Application, new_application_id
from kresheen.models.asset import AssetType
from kresheen.storage.repository import Repository

SystemType = Literal["web_app", "api_backend", "kubernetes_microservices", "data_pipeline", "ai_rag_app"]
UserGroup = Literal["public", "customers", "staff", "partners"]
Authentication = Literal["none", "password", "sso", "api_keys"]
DataKind = Literal["personal", "health", "payment", "credentials"]
ThirdParty = Literal["payments", "email", "identity_provider", "llm_api", "analytics"]


class IntakeAnswers(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    system_type: SystemType
    users: list[UserGroup] = Field(min_length=1, max_length=4)
    authentication: Authentication
    # Empty means the user answered that it handles no sensitive data.
    data: list[DataKind] = Field(default_factory=list, max_length=4)
    third_parties: list[ThirdParty] = Field(default_factory=list, max_length=5)
    has_admin: bool = False

    @field_validator("users", "data", "third_parties")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


@dataclass(frozen=True)
class Option:
    id: str
    label: str
    help: str = ""


SYSTEM_TYPES = (
    Option(
        "web_app",
        "A web application",
        "Browsers talk to a web front end backed by an application server and a database.",
    ),
    Option("api_backend", "An API or mobile backend", "Clients call an API gateway and service backed by a database."),
    Option(
        "kubernetes_microservices",
        "Microservices on Kubernetes",
        "An ingress in front of services running in a cluster, backed by a database.",
    ),
    Option("data_pipeline", "A data pipeline", "Data is ingested, processed and stored in a warehouse."),
    Option(
        "ai_rag_app",
        "An AI or chat assistant over your documents",
        "A chat front end, an orchestrator, a document store, a vector database and a model.",
    ),
)
USER_GROUPS = (
    Option("public", "Anyone on the internet", "Anonymous visitors."),
    Option("customers", "Customers with accounts"),
    Option("staff", "Your own staff"),
    Option("partners", "Partner systems", "Other organisations' systems calling yours."),
)
AUTHENTICATION = (
    Option("password", "Username and password"),
    Option("sso", "Single sign-on", "An identity provider (OIDC or SAML)."),
    Option("api_keys", "API keys or tokens"),
    Option("none", "No login", "Anyone who can reach it can use it."),
)
DATA_KINDS = (
    Option("personal", "Personal data", "Names, emails, addresses and similar (PII)."),
    Option("health", "Health data", "Medical or health records (PHI)."),
    Option("payment", "Payment card data", "Card numbers and related (PCI)."),
    Option("credentials", "Credentials or secrets", "Passwords, keys, tokens."),
)
THIRD_PARTIES = (
    Option("payments", "A payment provider"),
    Option("email", "An email or notification service"),
    Option("identity_provider", "An identity provider", "For single sign-on."),
    Option("llm_api", "A hosted LLM API", "Sends prompts to an external model provider."),
    Option("analytics", "An analytics service"),
)

_CLASSIFICATION = {"personal": "PII", "health": "PHI", "payment": "PCI", "credentials": "Credentials"}
_USER_NAMES = {
    "public": "Anonymous visitor",
    "customers": "Customer",
    "staff": "Staff member",
    "partners": "Partner system",
}
_USER_BOUNDARY = {"public": "Internet", "customers": "Internet", "staff": "Corporate network", "partners": "Internet"}
_THIRD_PARTY_NAMES = {
    "payments": "Payment provider",
    "email": "Email service",
    "identity_provider": "Identity provider",
    "llm_api": "LLM provider API",
    "analytics": "Analytics service",
}
_THIRD_PARTY_LABELS = {
    "payments": "card payments",
    "email": "notifications",
    "identity_provider": "SSO login",
    "llm_api": "prompts and responses",
    "analytics": "usage events",
}
_USER_FLOW_LABEL = {
    "web_app": "HTTPS",
    "api_backend": "HTTPS API calls",
    "kubernetes_microservices": "HTTPS",
    "data_pipeline": "data upload",
    "ai_rag_app": "HTTPS chat",
}

_P, _D, _E = AssetType.PROCESS, AssetType.DATA_STORE, AssetType.EXTERNAL_ENTITY


@dataclass
class IntakeModel:
    components: list[ComponentSpec]
    flows: list[FlowSpec]


def _stated(facts: dict[str, bool | str], element_type: str) -> dict[str, bool | str]:
    """Keeps the facts this installation can store: an AI/ML marker only exists when a plugin methodology reads it."""
    known = known_property_keys(element_type)
    return {key: value for key, value in facts.items() if key in known}


def build_intake_model(answers: IntakeAnswers) -> IntakeModel:
    """Pure: answers in, components/connections/stated facts out."""
    authenticates = answers.authentication != "none"
    third_parties = list(answers.third_parties)
    if answers.authentication == "sso" and "identity_provider" not in third_parties:
        third_parties.append("identity_provider")
    classification = ", ".join(_CLASSIFICATION[kind] for kind in answers.data)

    def store_facts(extra: dict[str, bool | str] | None = None) -> dict[str, bool | str]:
        facts: dict[str, bool | str] = dict(extra or {})
        if classification:
            facts["data_classification"] = classification
            if "credentials" in answers.data:
                facts["stores_credentials"] = True
        else:
            facts["no_sensitive_data"] = True
        return facts

    auth_fact: dict[str, bool | str] = {"authenticates_callers": authenticates}
    components: list[ComponentSpec] = []
    flows: list[FlowSpec] = []

    # Who reaches it.
    entry_name = {
        "web_app": "Web frontend",
        "api_backend": "API gateway",
        "kubernetes_microservices": "Ingress",
        "data_pipeline": "Ingestion service",
        "ai_rag_app": "Chat frontend",
    }[answers.system_type]
    backend_name = {
        "web_app": "Application server",
        "api_backend": "API service",
        "kubernetes_microservices": "Backend service",
        "data_pipeline": "Processing job",
        "ai_rag_app": "Orchestrator API",
    }[answers.system_type]
    store_name = {
        "web_app": "Database",
        "api_backend": "Database",
        "kubernetes_microservices": "Database",
        "data_pipeline": "Data warehouse",
        "ai_rag_app": "Document store",
    }[answers.system_type]
    web_facing = answers.system_type in ("web_app", "ai_rag_app")
    backend_boundary = "Kubernetes cluster" if answers.system_type == "kubernetes_microservices" else "Application"

    for group in answers.users:
        components.append(ComponentSpec(_USER_NAMES[group], _E, _USER_BOUNDARY[group]))
        flows.append(FlowSpec(_USER_NAMES[group], entry_name, _USER_FLOW_LABEL[answers.system_type]))

    entry_facts: dict[str, bool | str] = dict(auth_fact)
    if web_facing:
        entry_facts["is_web_application"] = True
    components.append(ComponentSpec(entry_name, _P, "DMZ", entry_facts))
    components.append(ComponentSpec(backend_name, _P, backend_boundary, dict(auth_fact)))
    components.append(ComponentSpec(store_name, _D, "Data", store_facts()))
    flows.append(
        FlowSpec(entry_name, backend_name, "gRPC/HTTP" if answers.system_type == "kubernetes_microservices" else "REST")
    )
    store_flow_facts: dict[str, bool | str] = {"data_classification": classification} if classification else {}
    flows.append(
        FlowSpec(
            backend_name,
            store_name,
            "writes" if answers.system_type == "data_pipeline" else "SQL",
            dict(store_flow_facts),
        )
    )
    primary_store = store_name

    if answers.system_type == "ai_rag_app":
        components.append(
            ComponentSpec(
                "Vector database", _D, "Data", _stated(store_facts({"is_ai_ml_component": True}), "data_store")
            )
        )
        flows.append(FlowSpec(backend_name, "Vector database", "similarity search", dict(store_flow_facts)))
        if "llm_api" not in third_parties:
            components.append(
                ComponentSpec("Model server", _P, "Application", _stated({"is_ai_ml_component": True}, "process"))
            )
            flows.append(FlowSpec(backend_name, "Model server", "prompts and responses"))

    for kind in third_parties:
        name = _THIRD_PARTY_NAMES[kind]
        components.append(ComponentSpec(name, _E, "Third party"))
        source = entry_name if kind in ("identity_provider", "analytics") else backend_name
        facts: dict[str, bool | str] = {"data_classification": "PCI"} if kind == "payments" else {}
        flows.append(FlowSpec(source, name, _THIRD_PARTY_LABELS[kind], facts))

    if answers.has_admin:
        components.append(ComponentSpec("Administrator", _E, "Corporate network"))
        components.append(ComponentSpec("Admin panel", _P, "Internal admin", {"is_web_application": True}))
        flows.append(FlowSpec("Administrator", "Admin panel", "HTTPS admin UI"))
        flows.append(FlowSpec("Admin panel", primary_store, "SQL", dict(store_flow_facts)))

    return IntakeModel(components, flows)


def _summary(answers: IntakeAnswers) -> str:
    labels = {
        o.id: o.label for group in (SYSTEM_TYPES, USER_GROUPS, AUTHENTICATION, DATA_KINDS, THIRD_PARTIES) for o in group
    }
    parts = [
        f"Started from the guided intake: {labels[answers.system_type].lower()}",
        "used by " + ", ".join(labels[u].lower() for u in answers.users),
        "login: " + labels[answers.authentication].lower(),
        "sensitive data: " + (", ".join(labels[d].lower() for d in answers.data) or "none"),
    ]
    if answers.third_parties:
        parts.append("talks to " + ", ".join(labels[t].lower() for t in answers.third_parties))
    if answers.has_admin:
        parts.append("has an admin interface")
    return "; ".join(parts) + ". The diagram is a starting point: check it against the real system."


def create_application_from_intake(
    repo: Repository, owner_user_id: str, answers: IntakeAnswers, group_id: str | None = None
) -> Application:
    """Creates the application and its starter model. The caller runs it."""
    now = datetime.now(UTC)
    summary = _summary(answers)
    application = Application(
        id=new_application_id(),
        name=answers.name.strip(),
        description=f"{answers.description.strip()}\n\n{summary}".strip(),
        group_id=group_id,
        owner_user_id=owner_user_id,
        created_at=now,
        updated_at=now,
    )
    model = build_intake_model(answers)
    persist_manual_model(repo, application, owner_user_id, model.components, model.flows)
    return application


@dataclass(frozen=True)
class Template:
    id: str
    title: str
    description: str
    answers: dict[str, object]


# Canned answers, nothing more: picking one prefills the wizard, which the user then adjusts.
TEMPLATES = (
    Template(
        "customer_web_app",
        "Customer-facing web app",
        "A web application where customers log in and their personal data is stored in a database.",
        {
            "system_type": "web_app",
            "users": ["customers"],
            "authentication": "password",
            "data": ["personal"],
            "third_parties": ["email"],
            "has_admin": False,
        },
    ),
    Template(
        "web_shop",
        "Web shop with card payments",
        "A storefront taking card payments through a provider, with an admin panel for staff.",
        {
            "system_type": "web_app",
            "users": ["customers"],
            "authentication": "password",
            "data": ["personal", "payment"],
            "third_parties": ["payments", "email"],
            "has_admin": True,
        },
    ),
    Template(
        "partner_api",
        "API for partners",
        "An API that partner systems call with API keys.",
        {
            "system_type": "api_backend",
            "users": ["partners"],
            "authentication": "api_keys",
            "data": ["personal"],
            "third_parties": [],
            "has_admin": False,
        },
    ),
    Template(
        "k8s_platform",
        "Microservices on Kubernetes",
        "Services behind an ingress in a cluster, with single sign-on and an admin console.",
        {
            "system_type": "kubernetes_microservices",
            "users": ["customers", "staff"],
            "authentication": "sso",
            "data": ["personal"],
            "third_parties": [],
            "has_admin": True,
        },
    ),
    Template(
        "internal_pipeline",
        "Internal data pipeline",
        "Staff-fed data ingested, processed and stored in a warehouse.",
        {
            "system_type": "data_pipeline",
            "users": ["staff"],
            "authentication": "sso",
            "data": ["personal"],
            "third_parties": [],
            "has_admin": False,
        },
    ),
    Template(
        "ai_assistant",
        "AI assistant over your documents",
        "A chat assistant that answers from your documents using a hosted LLM.",
        {
            "system_type": "ai_rag_app",
            "users": ["customers"],
            "authentication": "password",
            "data": ["personal"],
            "third_parties": ["llm_api"],
            "has_admin": False,
        },
    ),
)
