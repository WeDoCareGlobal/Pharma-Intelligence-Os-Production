import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from pharma_next.api import create_application
from pharma_next.security import authenticate_bearer, require_tenant_role
from pharma_next.store import CaseStore


TOKEN = "test-token-that-is-at-least-32-characters-long"


def test_bearer_authentication_resolves_configured_identity(monkeypatch):
    monkeypatch.setenv(
        "PHARMA_SERVICE_IDENTITIES",
        json.dumps({TOKEN: {"tenant": "tenant-a", "subject": "alice", "roles": ["reader"]}}),
    )
    assert authenticate_bearer(f"Bearer {TOKEN}") == {
        "user_id": "alice",
        "tenant": "tenant-a",
        "roles": ["reader"],
    }


def test_missing_bearer_token_is_rejected():
    with pytest.raises(HTTPException) as exc:
        authenticate_bearer(None)
    assert exc.value.status_code == 401


def test_unknown_bearer_token_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHARMA_SERVICE_IDENTITIES",
        json.dumps({TOKEN: {"tenant": "tenant-a", "subject": "alice", "roles": ["reader"]}}),
    )
    with pytest.raises(HTTPException) as exc:
        authenticate_bearer("Bearer " + "x" * 40)
    assert exc.value.status_code == 401


def test_unconfigured_authentication_fails_closed(monkeypatch):
    monkeypatch.delenv("PHARMA_SERVICE_IDENTITIES", raising=False)
    with pytest.raises(HTTPException) as exc:
        authenticate_bearer("Bearer " + TOKEN)
    assert exc.value.status_code == 503


def test_tenant_and_role_are_both_enforced():
    user = {"user_id": "alice", "tenant": "tenant-a", "roles": ["reader"]}
    require_tenant_role(user, "reader", "tenant-a")
    with pytest.raises(HTTPException) as wrong_tenant:
        require_tenant_role(user, "reader", "tenant-b")
    assert wrong_tenant.value.status_code == 403
    with pytest.raises(HTTPException) as wrong_role:
        require_tenant_role(user, "approver", "tenant-a")
    assert wrong_role.value.status_code == 403


def test_api_rejects_spoofed_identity_header_and_scopes_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "PHARMA_SERVICE_IDENTITIES",
        json.dumps({TOKEN: {"tenant": "tenant-a", "subject": "alice", "roles": ["reader"]}}),
    )
    app = create_application(CaseStore(tmp_path / "cases.db"))
    client = TestClient(app)

    spoofed = client.get(
        "/v1/cases?tenant=tenant-a",
        headers={"X-User-Id": "alice"},
    )
    assert spoofed.status_code == 401

    authorized = client.get(
        "/v1/cases?tenant=tenant-a",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert authorized.status_code == 200
    assert authorized.json() == []

    cross_tenant = client.get(
        "/v1/cases?tenant=tenant-b",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert cross_tenant.status_code == 403
