"""Model completeness: what the model does not say yet, and how to say it
Derived on demand from the merged DFD and never stored;
answering an item stores an ordinary owner-stated element property."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Alternative(BaseModel):
    """A second way to answer: e.g. 'holds no sensitive data', which settles a
    classification question without asserting a class."""

    key: str
    value: bool
    label: str


class FixSpec(BaseModel):
    property_key: str
    kind: Literal["bool", "text"]
    # Suggested answers for a text property.
    options: list[str] = Field(default_factory=list)
    # A best guess for a bool property, with why, so a user confirms rather than invents.
    suggested_value: bool | None = None
    suggestion_reason: str = ""
    alternative: Alternative | None = None


class CompletenessItem(BaseModel):
    id: str
    check: str
    element_kind: Literal["component", "flow", "model"]
    element_id: str | None = None
    element_name: str = ""
    message: str
    # What changes in the results once this is answered.
    why: str
    impact: Literal["high", "medium", "low"]
    fix: FixSpec | None = None


class CompletenessOut(BaseModel):
    # Percentage of applicable questions already answered; None when nothing is
    # askable yet (an empty model, or one with no analysable content).
    score: int | None
    answered: int
    total: int
    items: list[CompletenessItem]
