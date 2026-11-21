import pytest
from app.core.config import settings


def test_seed_admin_login(client):
    """
    Test authenticating with seeded initial admin credentials.
    """
    login_payload = {
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD
    }
    response = client.post(f"{settings.API_PREFIX}/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == settings.ADMIN_USERNAME
    assert data["user"]["role"] == "ADMIN"
    assert "portal:admin" in data["user"]["permissions"]
    assert "portal:analyst" in data["user"]["permissions"]


def test_invalid_login_credentials(client):
    """
    Test authenticating with incorrect credentials.
    """
    login_payload = {
        "username": settings.ADMIN_USERNAME,
        "password": "WrongPassword123!"
    }
    response = client.post(f"{settings.API_PREFIX}/auth/login", json=login_payload)
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_unauthenticated_protected_route(client):
    """
    Test accessing protected Admin/Analyst endpoints without a Bearer token.
    """
    response = client.get(f"{settings.API_PREFIX}/audit-logs")
    assert response.status_code == 401


def test_user_creation_and_rbac(client):
    """
    Test creating a new Analyst user using Admin token, then verifying Analyst permissions.
    """
    # 1. Admin login
    admin_login = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD
    }).json()
    admin_token = admin_login["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Admin creates an Analyst user
    new_user_payload = {
        "username": "analyst1",
        "email": "analyst1@cyberguard.soc",
        "password": "AnalystPassword123!",
        "role": "ANALYST"
    }
    create_res = client.post(f"{settings.API_PREFIX}/auth/users", json=new_user_payload, headers=headers)
    assert create_res.status_code == 201
    created_user = create_res.json()
    assert created_user["username"] == "analyst1"
    assert created_user["role"] == "ANALYST"
    assert "portal:normal" in created_user["permissions"]
    assert "portal:analyst" in created_user["permissions"]

    # 3. Login as the new Analyst
    analyst_login = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": "analyst1",
        "password": "AnalystPassword123!"
    }).json()
    analyst_token = analyst_login["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 4. Analyst accesses audit logs (allowed for Analyst/Admin)
    audit_res = client.get(f"{settings.API_PREFIX}/audit-logs", headers=analyst_headers)
    assert audit_res.status_code == 200
    assert "items" in audit_res.json()

    # 5. Analyst attempts Admin-only user management endpoint (should be Forbidden 403)
    user_mgmt_res = client.get(f"{settings.API_PREFIX}/auth/users", headers=analyst_headers)
    assert user_mgmt_res.status_code == 403


def test_admin_can_update_user_role_and_analyst_cannot(client):
    admin_login = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={
            "username": settings.ADMIN_USERNAME,
            "password": settings.ADMIN_INITIAL_PASSWORD,
        },
    ).json()
    admin_headers = {"Authorization": f"Bearer {admin_login['access_token']}"}

    created = client.post(
        f"{settings.API_PREFIX}/auth/users",
        headers=admin_headers,
        json={
            "username": "role_update_user",
            "email": "role.update@example.com",
            "password": "ViewerPassword123!",
            "role": "VIEWER",
        },
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    updated = client.patch(
        f"{settings.API_PREFIX}/auth/users/{user_id}",
        headers=admin_headers,
        json={"role": "ANALYST"},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "ANALYST"

    analyst_login = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": "role_update_user", "password": "ViewerPassword123!"},
    ).json()
    analyst_headers = {"Authorization": f"Bearer {analyst_login['access_token']}"}
    denied = client.patch(
        f"{settings.API_PREFIX}/auth/users/{user_id}",
        headers=analyst_headers,
        json={"role": "VIEWER"},
    )
    assert denied.status_code == 403
    audit = client.get(f"{settings.API_PREFIX}/audit-logs", headers=admin_headers)
    assert audit.status_code == 200
    assert any(item["action"] == "USER_UPDATED" for item in audit.json()["items"])


@pytest.mark.parametrize("payload", [{}, {"role": None}])
def test_admin_user_update_rejects_empty_or_null_fields(client, admin_headers, payload):
    admin_id = client.get(
        f"{settings.API_PREFIX}/auth/me",
        headers=admin_headers,
    ).json()["id"]
    response = client.patch(
        f"{settings.API_PREFIX}/auth/users/{admin_id}",
        headers=admin_headers,
        json=payload,
    )
    assert response.status_code == 422


def test_admin_cannot_demote_last_active_admin(client, admin_headers):
    admin_id = client.get(
        f"{settings.API_PREFIX}/auth/me",
        headers=admin_headers,
    ).json()["id"]
    for update in ({"role": "VIEWER"}, {"is_active": False}):
        response = client.patch(
            f"{settings.API_PREFIX}/auth/users/{admin_id}",
            headers=admin_headers,
            json=update,
        )
        assert response.status_code == 409
        assert "last active administrator" in response.json()["detail"].lower()


def test_audit_logging_integrity(client):
    """
    Test that authentication events generate persistent audit entries.
    """
    admin_login = client.post(f"{settings.API_PREFIX}/auth/login", json={
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD
    }).json()
    headers = {"Authorization": f"Bearer {admin_login['access_token']}"}

    audit_res = client.get(f"{settings.API_PREFIX}/audit-logs", headers=headers)
    assert audit_res.status_code == 200
    items = audit_res.json()["items"]
    assert len(items) > 0
    actions = [item["action"] for item in items]
    assert "LOGIN_SUCCESS" in actions


def test_security_headers(client):
    """
    Test presence of HTTP security headers on API responses.
    """
    response = client.get(f"{settings.API_PREFIX}/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin-when-cross-origin" in response.headers.get("Referrer-Policy", "")


def test_sql_injection_defense(client, admin_headers):
    """
    Test that malicious SQL strings in search parameters are safely parameterized.
    """
    malicious_query = "' OR '1'='1"
    response = client.get(
        f"{settings.API_PREFIX}/detection/history",
        params={"threat_type": malicious_query},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
