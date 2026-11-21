import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.services.user_service import UserService


def test_production_requires_explicit_jwt_secret():
    with pytest.raises(ValidationError, match="SECRET_KEY must be configured"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SECRET_KEY="",
            ADMIN_INITIAL_PASSWORD="Secure-Admin-Password-123",
        )


def test_production_requires_strong_jwt_secret():
    with pytest.raises(ValidationError, match="SECRET_KEY must be at least 32 bytes"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SECRET_KEY="too-short",
            ADMIN_INITIAL_PASSWORD="Secure-Admin-Password-123",
        )


def test_production_requires_initial_admin_password():
    with pytest.raises(ValidationError, match="ADMIN_INITIAL_PASSWORD must be"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            SECRET_KEY="s" * 32,
            ADMIN_INITIAL_PASSWORD="",
        )


def test_nonproduction_generates_an_ephemeral_secret_when_unset():
    config = Settings(
        _env_file=None,
        APP_ENV="development",
        SECRET_KEY="",
        ADMIN_INITIAL_PASSWORD="",
    )

    assert len(config.SECRET_KEY.encode("utf-8")) >= 32
    assert config.ADMIN_INITIAL_PASSWORD == ""


def test_admin_seed_is_skipped_when_initial_password_is_unset(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_INITIAL_PASSWORD", "")
    monkeypatch.setattr(UserService, "get_by_username", lambda db, username: None)
    db = object()

    assert UserService.seed_initial_admin(db) is None
