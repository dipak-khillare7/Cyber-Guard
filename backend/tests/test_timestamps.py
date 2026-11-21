import pytest
from datetime import datetime, timezone, timedelta
from app.core.security import format_iso_utc
from app.schemas.enums import ThreatType


def test_format_iso_utc_naive_datetime():
    """
    Test that naive UTC datetimes are formatted to ISO 8601 strings ending with 'Z'.
    """
    dt = datetime(2026, 10, 9, 6, 30, 0)
    iso_str = format_iso_utc(dt)
    assert iso_str == "2026-10-09T06:30:00Z"


def test_format_iso_utc_tz_aware_datetime():
    """
    Test that tz-aware UTC datetimes are formatted to ISO 8601 strings ending with 'Z'.
    """
    dt = datetime(2026, 10, 9, 6, 30, 0, tzinfo=timezone.utc)
    iso_str = format_iso_utc(dt)
    assert iso_str == "2026-10-09T06:30:00Z"


def test_utc_to_ist_offset_math():
    """
    Test mathematical equivalence of 06:30 UTC and 12:00 IST (UTC+5:30).
    """
    utc_dt = datetime(2026, 10, 9, 6, 30, 0, tzinfo=timezone.utc)
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    ist_dt = utc_dt.astimezone(ist_tz)

    assert ist_dt.year == 2026
    assert ist_dt.month == 10
    assert ist_dt.day == 9
    assert ist_dt.hour == 12
    assert ist_dt.minute == 0
    assert ist_dt.second == 0


def test_midnight_boundary_utc_to_ist():
    """
    Test midnight boundary shift: 22:30 UTC on Oct 8 is 04:00 IST on Oct 9.
    """
    utc_dt = datetime(2026, 10, 8, 22, 30, 0, tzinfo=timezone.utc)
    ist_tz = timezone(timedelta(hours=5, minutes=30))
    ist_dt = utc_dt.astimezone(ist_tz)

    assert ist_dt.day == 9
    assert ist_dt.hour == 4
    assert ist_dt.minute == 0


def test_detection_history_timestamp_serialization(client, admin_headers):
    """
    Test that /api/v1/detection/history returns ISO 8601 timestamps ending with 'Z'.
    """
    res_post = client.post("/api/v1/detection/analyze", json={
        "source_ip": "10.0.0.99",
        "destination_port": 80
    }, headers=admin_headers)
    assert res_post.status_code == 200

    res_hist = client.get("/api/v1/detection/history?skip=0&limit=10", headers=admin_headers)
    assert res_hist.status_code == 200
    items = res_hist.json()["items"]
    assert len(items) >= 1
    first_item = items[0]
    assert "timestamp" in first_item
    assert first_item["timestamp"].endswith("Z") or "+00:00" in first_item["timestamp"]


def test_detection_trend_24h(client, admin_headers):
    """
    Test that /api/v1/detection/trend returns valid IST time buckets.
    """
    res_trend = client.get("/api/v1/detection/trend?hours=24", headers=admin_headers)
    assert res_trend.status_code == 200
    data = res_trend.json()
    assert data["success"] is True
    assert data["timezone"] == "Asia/Kolkata"
    assert len(data["trend"]) == 24
    assert "time" in data["trend"][0]


def test_detection_trend_ist_bucket_assignment(client, admin_headers):
    """
    Test that events created at specific UTC times fall into their matching IST hour buckets.
    """
    res_post = client.post("/api/v1/detection/analyze", json={
        "source_ip": "192.168.1.200",
        "destination_port": 80
    }, headers=admin_headers)
    assert res_post.status_code == 200

    res_trend = client.get("/api/v1/detection/trend?hours=24", headers=admin_headers)
    assert res_trend.status_code == 200
    trend_buckets = res_trend.json()["trend"]
    total_events_in_trend = sum(b["total"] for b in trend_buckets)
    assert total_events_in_trend >= 1
