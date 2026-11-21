from sqlalchemy import create_engine, inspect, text


def test_legacy_assessments_are_preserved_by_additive_schema_upgrade(monkeypatch):
    from app.database import init_db

    test_engine = create_engine("sqlite:///:memory:")
    with test_engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE website_assessments (
                id INTEGER PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                target_domain VARCHAR(260) NOT NULL,
                scheme VARCHAR(5) NOT NULL,
                risk_level VARCHAR(32) NOT NULL,
                risk_explanation VARCHAR(500) NOT NULL,
                provider_status VARCHAR(32) NOT NULL,
                provider_retrieved_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL
            )
        """))
        connection.execute(text("""
            INSERT INTO website_assessments (
                id, owner_user_id, target_domain, scheme, risk_level,
                risk_explanation, provider_status, provider_retrieved_at, created_at
            ) VALUES (
                7, 42, 'legacy.example', 'https', 'INSUFFICIENT_INFORMATION',
                'Existing result', 'NOT_CONFIGURED', '2025-01-01', '2025-01-01'
            )
        """))
    monkeypatch.setattr(init_db, "engine", test_engine)

    init_db._upgrade_website_assessment_schema()

    with test_engine.connect() as connection:
        row = connection.execute(
            text("""
                SELECT id, owner_user_id, target_domain, risk_score, analysis_status,
                       dns_status, dns_findings_json, idempotency_key
                FROM website_assessments WHERE id = 7
            """)
        ).one()
    indexes = inspect(test_engine).get_indexes("website_assessments")

    assert row.id == 7
    assert row.owner_user_id == 42
    assert row.target_domain == "legacy.example"
    assert row.risk_score is None
    assert row.analysis_status == "LEGACY"
    assert row.dns_status == "NOT_CHECKED"
    assert row.dns_findings_json is None
    assert row.idempotency_key is None
    assert any(index["name"] == "uq_website_assessments_owner_idempotency_key" for index in indexes)
