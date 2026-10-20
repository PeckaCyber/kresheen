"""ApplicationGroup: a team (or other owner) that groups several Applications.

Applications reference a group by `Application.group_id`; an Application with
no group_id belongs to the built-in "Ungrouped" bucket, which is virtual (no
row), so existing Applications need no migration.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


def new_group_id() -> str:
    return f"GRP-{uuid.uuid4().hex[:16]}"


class ApplicationGroup(BaseModel):
    id: str
    name: str
    description: str = ""
    owner_user_id: str
    created_at: datetime
    updated_at: datetime
