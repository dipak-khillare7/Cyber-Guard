def test_create_valid_event(client, admin_headers):
    payload = {
        "source_ip": "192.168.1.15",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "protocol": "TCP",
        "duration": 1.25,
        "packet_count": 12,
        "byte_count": 1024,
        "event_type": "NETWORK",
        "raw_data": "GET /index.html HTTP/1.1"
    }
    response = client.post("/api/v1/events", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["id"] is not None
    assert data["source_ip"] == "192.168.1.15"
    assert data["destination_port"] == 80


def test_get_event_by_id(client, admin_headers):
    # Create event first
    payload = {"source_ip": "172.16.0.4", "destination_port": 443, "event_type": "NETWORK"}
    res_create = client.post("/api/v1/events", json=payload, headers=admin_headers)
    event_id = res_create.json()["id"]

    response = client.get(f"/api/v1/events/{event_id}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["id"] == event_id


def test_get_missing_event(client, admin_headers):
    response = client.get("/api/v1/events/999999", headers=admin_headers)
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert data["detail"]["code"] == "EVENT_NOT_FOUND"


def test_invalid_ip_validation(client, admin_headers):
    payload = {"source_ip": "999.999.999.999", "destination_port": 80}
    response = client.post("/api/v1/events", json=payload, headers=admin_headers)
    assert response.status_code == 422


def test_invalid_port_validation(client, admin_headers):
    payload = {"source_ip": "192.168.1.1", "destination_port": 70000}
    response = client.post("/api/v1/events", json=payload, headers=admin_headers)
    assert response.status_code == 422


def test_list_events(client, admin_headers):
    client.post("/api/v1/events", json={"source_ip": "10.0.0.1", "destination_port": 22}, headers=admin_headers)
    client.post("/api/v1/events", json={"source_ip": "10.0.0.2", "destination_port": 80}, headers=admin_headers)

    response = client.get("/api/v1/events?skip=0&limit=10", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2
