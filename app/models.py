from typing import Any
from pydantic import BaseModel, Field


class Event(BaseModel):
    timestamp: float
    session_id: str = Field(min_length=1, max_length=128)
    source_ip: str = Field(max_length=64)
    sensor: str = Field(default='replay', max_length=32)
    target_host: str = Field(default='dc01', max_length=64)
    action: str = Field(max_length=64)
    target: str = Field(default='', max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReplayRequest(BaseModel):
    scenario: str = 'replay_full_attack'
    paced: bool = True
    pace_seconds: float = Field(default=2, ge=0.2, le=10)
