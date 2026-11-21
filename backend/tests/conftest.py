import secrets
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.connection import Base, get_db
from app.services.user_service import UserService
from app.core.config import settings

if not settings.ADMIN_INITIAL_PASSWORD:
    settings.ADMIN_INITIAL_PASSWORD = secrets.token_urlsafe(18)

# Use in-memory SQLite database for automated tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """
    Creates fresh database schema for each test session and seeds initial admin.
    """
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        UserService.seed_initial_admin(session)
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """
    FastAPI TestClient with overridden get_db dependency.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def admin_headers(client):
    """
    Helper fixture to return Authorization header for initial admin.
    """
    login_payload = {
        "username": settings.ADMIN_USERNAME,
        "password": settings.ADMIN_INITIAL_PASSWORD
    }
    res = client.post("/api/v1/auth/login", json=login_payload)
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
