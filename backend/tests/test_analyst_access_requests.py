from app.core.config import settings
from app.models.user import User, UserRole


def _create_viewer(client, admin_headers, username="access_request_user"):
    response = client.post(
        f"{settings.API_PREFIX}/auth/users",
        headers=admin_headers,
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "ViewerPassword123!",
            "role": "VIEWER",
        },
    )
    assert response.status_code == 201
    login = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": username, "password": "ViewerPassword123!"},
    )
    assert login.status_code == 200
    return response.json()["id"], {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_viewer_request_is_pending_without_granting_analyst_access(client, admin_headers, db_session):
    user_id, viewer_headers = _create_viewer(client, admin_headers)

    created = client.post(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers)
    assert created.status_code == 201
    assert created.json()["status"] == "PENDING"
    assert created.json()["requester_user_id"] == user_id
    assert db_session.get(User, user_id).role == UserRole.VIEWER

    own_request = client.get(
        f"{settings.API_PREFIX}/access-requests/analyst/me",
        headers=viewer_headers,
    )
    assert own_request.status_code == 200
    assert own_request.json()["id"] == created.json()["id"]

    duplicate = client.post(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers)
    assert duplicate.status_code == 409
    assert client.get(f"{settings.API_PREFIX}/audit-logs", headers=viewer_headers).status_code == 403
    assert client.get(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers).status_code == 403


def test_admin_rejection_keeps_role_and_allows_later_request(client, admin_headers, db_session):
    user_id, viewer_headers = _create_viewer(client, admin_headers, "rejected_access_user")
    created = client.post(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers)
    request_id = created.json()["id"]

    rejected = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "REJECT"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert db_session.get(User, user_id).role == UserRole.VIEWER

    resubmitted = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst",
        headers=viewer_headers,
    )
    assert resubmitted.status_code == 201
    assert resubmitted.json()["status"] == "PENDING"


def test_admin_approval_grants_role_only_as_part_of_decision(client, admin_headers, db_session):
    user_id, viewer_headers = _create_viewer(client, admin_headers, "approved_access_user")
    created = client.post(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers)
    request_id = created.json()["id"]

    pending = client.get(
        f"{settings.API_PREFIX}/access-requests/analyst",
        headers=admin_headers,
    )
    assert pending.status_code == 200
    assert any(item["id"] == request_id for item in pending.json()["items"])
    assert db_session.get(User, user_id).role == UserRole.VIEWER

    approved = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "APPROVE"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert db_session.get(User, user_id).role == UserRole.ANALYST

    refreshed_profile = client.get(f"{settings.API_PREFIX}/auth/me", headers=viewer_headers)
    assert refreshed_profile.status_code == 200
    assert refreshed_profile.json()["role"] == "ANALYST"
    assert "portal:analyst" in refreshed_profile.json()["permissions"]
    assert client.get(f"{settings.API_PREFIX}/audit-logs", headers=viewer_headers).status_code == 200


def test_only_admin_can_decide_and_decisions_are_one_time(client, admin_headers):
    user_id, viewer_headers = _create_viewer(client, admin_headers, "review_access_user")
    created = client.post(f"{settings.API_PREFIX}/access-requests/analyst", headers=viewer_headers)
    request_id = created.json()["id"]

    denied = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst/{request_id}/decision",
        headers=viewer_headers,
        json={"decision": "APPROVE"},
    )
    assert denied.status_code == 403

    approved = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "APPROVE"},
    )
    assert approved.status_code == 200

    repeated = client.post(
        f"{settings.API_PREFIX}/access-requests/analyst/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "REJECT"},
    )
    assert repeated.status_code == 409
    assert user_id == approved.json()["requester_user_id"]
