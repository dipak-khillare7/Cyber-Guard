from app.core.config import settings
from app.models.user import UserRole
from app.schemas.user import UserCreate
from app.services.user_service import UserService


def _create_viewer_headers(client, db_session):
    UserService.create_user(
        db_session,
        UserCreate(
            username="legacy_viewer",
            email="legacy.viewer@example.com",
            password="ViewerPassword123!",
            role=UserRole.VIEWER,
        ),
    )
    response = client.post(
        f"{settings.API_PREFIX}/auth/login",
        json={"username": "legacy_viewer", "password": "ViewerPassword123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_legacy_viewer_has_no_soc_or_removed_user_feature_api_access(client, db_session):
    headers = _create_viewer_headers(client, db_session)
    protected_paths = (
        "/events",
        "/events/1",
        "/statistics",
        "/detection/history",
        "/detection/trend",
    )

    for path in protected_paths:
        response = client.get(f"{settings.API_PREFIX}{path}", headers=headers)
        assert response.status_code == 403, path

    assert client.post(
        f"{settings.API_PREFIX}/events",
        json={"source_ip": "192.0.2.10", "destination_port": 443},
        headers=headers,
    ).status_code == 403
    assert client.post(
        f"{settings.API_PREFIX}/detection/analyze",
        json={},
        headers=headers,
    ).status_code == 403
    assert client.get(
        f"{settings.API_PREFIX}/website-assessments",
        headers=headers,
    ).status_code == 404
    assert client.post(
        f"{settings.API_PREFIX}/website-assessments/analyze",
        json={},
        headers=headers,
    ).status_code == 404
    assert client.post(
        f"{settings.API_PREFIX}/access-requests/analyst",
        headers=headers,
    ).status_code == 404
