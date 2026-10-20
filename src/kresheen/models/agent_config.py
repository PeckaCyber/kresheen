"""AgentConfig: a person's own settings for the optional AI assist.

One row per user: their Anthropic API key (stored only as a reference), the model they chose and, optionally, an
Anthropic workspace ID. `api_key_ref` is never the raw key; it points into `secrets/store.py`'s `DbSecretStore`.

`default_model` defaults to `None`, not a hardcoded model id: "no AI, rule-based threat modeling only" is a
first-class, permanent choice, not a transient pre-setup state. When a model is set, the dashboard offers the choice
from Anthropic's live model list for the user's own key (`dashboard/routes/api_agent_config.py`) rather than a
hardcoded guess at model names.

`scope` and `scope_id` are the stored lookup columns. Only `scope="user"` is ever written; `"application"` is kept in
the type so old rows still load. The config is stored as a JSON blob, so keys a row once carried that this model no
longer has are ignored on load.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


def new_agent_config_id() -> str:
    return f"AGENT-{uuid.uuid4().hex[:16]}"


class AgentConfig(BaseModel):
    id: str
    scope: Literal["user", "application"]
    scope_id: str
    provider: Literal["anthropic"] = "anthropic"
    api_key_ref: str | None = None  # None is valid iff default_model is also None (rule-based-only, no key at all)
    default_model: str | None = None
    # Anthropic workspace to bill and scope requests to. Needed only for an organisation-level key that is not tied to
    # one workspace (Anthropic then rejects every request without the `anthropic-workspace-id` header). Not a secret.
    workspace_id: str | None = None
    created_at: datetime
    updated_at: datetime
