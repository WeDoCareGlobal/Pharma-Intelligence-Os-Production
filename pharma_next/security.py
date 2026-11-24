from __future__ import annotations

"""Fail-closed bearer-token authentication and tenant-scoped authorization.

Configure PHARMA_SERVICE_IDENTITIES as a JSON object keyed by long, random
bearer tokens. Each value must contain tenant, subject, and a roles array.
Example (use generated secrets; never commit real values):
{"<at-least-32-character-token>":{"tenant":"demo","subject":"reviewer-1","roles":["reader","reviewer"]}}
"""

import hmac
import json
import os
from typing import Any

from fastapi import HTTPException


def _identities() -> dict[str, dict[str, Any]]:
    raw = os.environ.get("PHARMA_SERVICE_IDENTITIES", "")
    if not raw:
        raise HTTPException(
            status_code=503,
            detail="authentication is not configured; set PHARMA_SERVICE_IDENTITIES",
        )
    try:
        configured = json.loads(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=503, detail="authentication configuration is invalid")
    if not isinstance(configured, dict) or not configured:
        raise HTTPException(status_code=503, detail="authentication configuration is invalid")

    for token, identity in configured.items():
        if (
            not isinstance(token, str)
            or len(token) < 32
            or not isinstance(identity, dict)
            or not isinstance(identity.get("tenant"), str)
            or not identity["tenant"].strip()
            or not isinstance(identity.get("subject"), str)
            or not identity["subject"].strip()
            or not isinstance(identity.get("roles"), list)
            or not identity["roles"]
            or any(not isinstance(role, str) or not role.strip() for role in identity["roles"])
        ):
            raise HTTPException(status_code=503, detail="authentication configuration is invalid")
    return configured


def authenticate_bearer(authorization: str | None) -> dict[str, Any]:
    """Resolve a bearer token to a configured service identity; never trust user headers."""
    if not authorization:
        raise HTTPException(status_code=401, detail="bearer token required")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="invalid authorization header")

    configured = _identities()
    for candidate, identity in configured.items():
        if hmac.compare_digest(candidate, token.strip()):
            return {
                "user_id": identity["subject"].strip(),
                "tenant": identity["tenant"].strip(),
                "roles": [role.strip() for role in identity["roles"]],
            }
    raise HTTPException(status_code=401, detail="invalid bearer token")


def require_tenant_role(
    user: dict[str, Any],
    role: str,
    tenant: str,
    compliance: Any = None,
    compliance_enabled: bool = False,
) -> None:
    """Enforce tenant binding and role authorization on every protected route."""
    effective_tenant = tenant or user.get("tenant", "")
    if not effective_tenant or effective_tenant != user.get("tenant"):
        raise HTTPException(status_code=403, detail="tenant access denied")

    if compliance_enabled:
        if compliance is None or not compliance.enabled:
            raise HTTPException(status_code=503, detail="compliance authorization is unavailable")
        if role == "admin":
            allowed = compliance.has_role(user["user_id"], "admin", effective_tenant)
        else:
            allowed = compliance.has_role(user["user_id"], role, effective_tenant) or compliance.has_role(
                user["user_id"], "admin", effective_tenant
            )
    else:
        roles = set(user.get("roles", []))
        allowed = "admin" in roles or role in roles

    if not allowed:
        raise HTTPException(status_code=403, detail=f"role {role} required on tenant {effective_tenant}")
