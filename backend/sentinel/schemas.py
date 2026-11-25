"""Request and response models for the HTTP API."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")
Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["open", "acknowledged", "resolved"]
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    role: str
    is_active: bool


class UserCreate(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=10, max_length=200)
    role: Literal["analyst", "admin"] = "analyst"

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL.match(v):
            raise ValueError("not a valid email address")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class IngestIn(BaseModel):
    source: Literal["auth", "nginx"]
    host: str | None = Field(default=None, max_length=120)
    lines: list[str] = Field(min_length=1, max_length=5000)


class IngestOut(BaseModel):
    accepted: int
    queued: bool
    parsed: int | None = None
    alerts: int | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime
    source: str
    kind: str
    host: str
    ip: str | None
    user: str | None
    method: str | None
    path: str | None
    status: int | None
    command: str | None
    raw: str


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    title: str
    severity: Severity
    description: str
    group_by: str | None
    key: str
    count: int
    first_seen: datetime
    last_seen: datetime
    status: AlertStatus
    assignee_id: int | None
    evidence: list[str]
    history: list[dict]
    created_at: datetime


class AlertPatch(BaseModel):
    status: AlertStatus | None = None
    note: str | None = Field(default=None, max_length=1000)
    assign_to_me: bool = False


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: int | None = None


class TimelinePoint(BaseModel):
    t: datetime
    auth: int
    nginx: int
    alerts: int


class Counted(BaseModel):
    key: str
    count: int


class Overview(BaseModel):
    since: datetime
    events: int
    events_by_source: dict[str, int]
    open_alerts: dict[str, int]
    alerts_in_window: int
    timeline: list[TimelinePoint]
    top_offenders: list[Counted]
    top_rules: list[Counted]
