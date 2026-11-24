"""API-level tests for the CFR 11 compliance endpoints."""

import json

from fastapi.testclient import TestClient

from pharma_next.api import create_application
from pharma_next.cfr11 import CFR11Compliance
from pharma_next.store import CaseStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64


def _app(tmp_path, monkeypatch):
    identities = {
        "test-token-for-" + user + "-012345678901234567890123": {
            "tenant": "t", "subject": user, "roles": ["reader"]
        }
        for user in ["alice", "bob", "carol", "dave", "eve"]
    }
    monkeypatch.setenv("PHARMA_SERVICE_IDENTITIES", json.dumps(identities))
    monkeypatch.setenv("CFR11_ENABLE", "1")
    monkeypatch.setenv("CFR11_DUAL_AUTHORIZATION", "1")
    signing_key = Ed25519PrivateKey.generate()
    enc_key = AESGCM.generate_key(256)
    monkeypatch.setenv("CFR11_SIGNING_KEY", base64.b64encode(signing_key.private_bytes_raw()).decode("ascii"))
    monkeypatch.setenv("CFR11_ENCRYPTION_KEY", base64.b64encode(enc_key).decode("ascii"))
    db = str(tmp_path / "api.db")
    cfr11 = CFR11Compliance(
        db, enabled=True, signing_key=signing_key, encryption_key=AESGCM(enc_key)
    )
    for user, role in [("alice", "editor"), ("alice", "reader"), ("bob", "reviewer"), ("bob", "reader"),
                       ("carol", "approver"), ("carol", "reader"), ("dave", "approver"), ("dave", "reader"),
                       ("eve", "admin"), ("eve", "reader")]:
        cfr11.assign_role(user, role, "t")
    store = CaseStore(db, cfr11=cfr11)
    return TestClient(create_application(store)), cfr11


def _headers(user):
    token = "test-token-for-" + user + "-012345678901234567890123"
    return {"Authorization": f"Bearer {token}"}


def test_requires_authentication(tmp_path, monkeypatch):
    client, _ = _app(tmp_path, monkeypatch)
    r = client.post("/v1/cases", params={"tenant": "t"},
                    json={"body": {"summary": "s", "source_refs": []}})
    assert r.status_code == 401


def test_create_and_review_flow(tmp_path, monkeypatch):
    client, cfr11 = _app(tmp_path, monkeypatch)
    r = client.post("/v1/cases", params={"tenant": "t"}, headers=_headers("alice"),
                    json={"body": {"summary": "summary", "source_refs": ["ref-1"]}})
    assert r.status_code == 201, r.text
    case = r.json()
    assert case["state"] == "draft"

    # Non-reviewer rejected.
    r = client.post("/v1/cases/{}/review".format(case["id"]), params={"tenant": "t"},
                    headers=_headers("alice"), json={"expected_version": case["version"]})
    assert r.status_code == 403

    # Independent reviewer approves review.
    r = client.post("/v1/cases/{}/review".format(case["id"]), params={"tenant": "t"},
                    headers=_headers("bob"), json={"expected_version": case["version"]})
    assert r.status_code == 200, r.text
    reviewed = r.json()
    assert reviewed["state"] == "reviewed"

    # First approver: not enough (dual authorization).
    r = client.post("/v1/cases/{}/approve".format(case["id"]), params={"tenant": "t"},
                    headers=_headers("carol"), json={"expected_version": r.json()["version"]})
    assert r.status_code == 200
    assert r.json()["state"] == "reviewed"

    # Double authorization by same user rejected.
    r = client.post("/v1/cases/{}/approve".format(case["id"]), params={"tenant": "t"},
                    headers=_headers("carol"), json={"expected_version": r.json()["version"]})
    assert r.status_code == 409

    # Second approver releases.
    r = client.post("/v1/cases/{}/approve".format(case["id"]), params={"tenant": "t"},
                    headers=_headers("dave"), json={"expected_version": reviewed["version"]})
    assert r.status_code == 200
    assert r.json()["state"] == "approved"

    # Export needs approver role and approved state.
    r = client.get("/v1/cases/{}/draft".format(case["id"]), params={"tenant": "t"},
                   headers=_headers("alice"))
    assert r.status_code == 403
    r = client.get("/v1/cases/{}/draft".format(case["id"]), params={"tenant": "t"},
                   headers=_headers("carol"))
    assert r.status_code == 200
    assert "sha256" in r.json()


def test_reader_cannot_write(tmp_path, monkeypatch):
    client, _ = _app(tmp_path, monkeypatch)
    # bob is only a reviewer: cannot create.
    r = client.post("/v1/cases", params={"tenant": "t"}, headers=_headers("bob"),
                    json={"body": {"summary": "s", "source_refs": []}})
    assert r.status_code == 403


def test_audit_trail_and_verify(tmp_path, monkeypatch):
    client, _ = _app(tmp_path, monkeypatch)
    client.post("/v1/cases", params={"tenant": "t"}, headers=_headers("alice"),
                json={"body": {"summary": "s", "source_refs": []}})
    r = client.get("/v1/cfr11/audit", params={"tenant": "t", "verify": 1}, headers=_headers("eve"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["events"]) >= 1
    assert body["verification"]["ok"] is True
    assert body["verification"]["events_checked"] >= 1

    r = client.get("/v1/cfr11/audit/verify", params={"tenant": "t"}, headers=_headers("eve"))
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_e_signature_endpoints_enforce_action_roles_and_case_binding(tmp_path, monkeypatch):
    client, _ = _app(tmp_path, monkeypatch)
    created = client.post(
        "/v1/cases", params={"tenant": "t"}, headers=_headers("alice"),
        json={"body": {"summary": "signature target", "source_refs": []}},
    )
    assert created.status_code == 201, created.text
    case = created.json()
    params = {"tenant": "t"}
    payload = {
        "purpose": "case_review",
        "payload": {"decision": "reviewed"},
        "case_id": case["id"],
        "version": case["version"],
    }

    # A reader/editor cannot sign a regulated review action.
    denied = client.post("/v1/cfr11/e-sign", params=params, headers=_headers("alice"), json=payload)
    assert denied.status_code == 403

    # The reviewer may sign the review action.
    signed = client.post("/v1/cfr11/e-sign", params=params, headers=_headers("bob"), json=payload)
    assert signed.status_code == 200, signed.text
    sig_id = signed.json()["id"]

    verified = client.get("/v1/cfr11/e-sign/{}/verify".format(sig_id), headers=_headers("eve"))
    assert verified.status_code == 200
    assert verified.json()["valid"] is True

    # The same user cannot reuse the same signature binding.
    duplicate = client.post("/v1/cfr11/e-sign", params=params, headers=_headers("bob"), json=payload)
    assert duplicate.status_code == 409

    # Approval signatures require an approver, not merely a reviewer.
    approval_payload = {
        "purpose": "case_approval",
        "payload": {"decision": "approved"},
        "case_id": case["id"],
        "version": case["version"],
    }
    approval = client.post(
        "/v1/cfr11/e-sign", params=params, headers=_headers("carol"), json=approval_payload
    )
    assert approval.status_code == 200, approval.text

    unsupported = client.post(
        "/v1/cfr11/e-sign", params=params, headers=_headers("bob"),
        json={**payload, "purpose": "arbitrary_admin_action"},
    )
    assert unsupported.status_code == 400

    missing_binding = client.post(
        "/v1/cfr11/e-sign", params=params, headers=_headers("bob"),
        json={"purpose": "case_review", "payload": {"decision": "reviewed"}},
    )
    assert missing_binding.status_code == 422


def test_audit_chain_verifies_interleaved_tenants_globally(tmp_path, monkeypatch):
    _, cfr11 = _app(tmp_path, monkeypatch)
    cfr11.record_event(None, "tenant-a", "alice", "created", body={"id": "a1"})
    cfr11.record_event(None, "tenant-b", "bob", "created", body={"id": "b1"})
    cfr11.record_event(None, "tenant-a", "alice", "reviewed", body={"id": "a2"})

    report = cfr11.verify_chain("tenant-a")
    assert report["ok"] is True
    assert report["events_checked"] == 3


def test_rbac_role_endpoint(tmp_path, monkeypatch):
    client, _ = _app(tmp_path, monkeypatch)
    r = client.post("/v1/cfr11/roles", headers=_headers("alice"),
                    json={"user_id": "fay", "role": "reader", "tenant": "t"})
    assert r.status_code == 403  # alice is not admin
    r = client.post("/v1/cfr11/roles", headers=_headers("eve"),
                    json={"user_id": "fay", "role": "reader", "tenant": "t"})
    assert r.status_code == 200
    r = client.get("/v1/cfr11/roles", params={"user_id": "fay", "tenant": "t"},
                   headers=_headers("eve"))
    assert r.status_code == 200
    assert "reader" in r.json()["roles"]


def test_tls_middleware_rejects_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("CFR11_REQUIRE_TLS", "1")
    client, _ = _app(tmp_path, monkeypatch)
    r = client.get("/health")
    assert r.status_code == 403
    r = client.get("/health", headers={"x-forwarded-proto": "https"})
    assert r.status_code == 200
    assert r.headers["strict-transport-security"].startswith("max-age=31536000")
