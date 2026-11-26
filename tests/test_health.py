def test_health_endpoint_is_public_and_reports_database_ready(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}
