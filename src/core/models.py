from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ==========================================================
# Severity
# ==========================================================

class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ==========================================================
# Form Models
# ==========================================================

@dataclass
class FormField:
    name: str
    type: str = "text"
    value: Optional[str] = None
    required: bool = False


@dataclass
class FormInfo:
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)


# ==========================================================
# Request / Response Models
# ==========================================================

@dataclass
class RequestData:
    params: dict[str, str] = field(default_factory=dict)
    form_data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class ResponseData:
    status_code: int = 0
    content_type: str = ""
    headers: dict[str, str] = field(default_factory=dict)


# ==========================================================
# Endpoint
# ==========================================================

@dataclass
class Endpoint:
    url: str
    method: str = "GET"

    request: RequestData = field(default_factory=RequestData)
    response: ResponseData = field(default_factory=ResponseData)

    forms: list[FormInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)

    is_form: bool = False


# ==========================================================
# Target
# ==========================================================

@dataclass
class Target:
    base_url: str
    endpoints: list[Endpoint] = field(default_factory=list)


# ==========================================================
# Finding
# ==========================================================

@dataclass
class Finding:
    title: str
    severity: Severity

    endpoint: str

    description: str

    remediation: str

    evidence: Optional[str] = None

    parameter: Optional[str] = None

    payload: Optional[str] = None

    references: list[str] = field(default_factory=list)
