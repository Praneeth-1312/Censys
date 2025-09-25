import pytest
import json
import os
import sys
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app, HOSTS, UPLOAD_TIMESTAMP

client = TestClient(app)

# Global test setup and teardown
@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Global setup and teardown for all tests"""
    # Setup: Clear global state before each test
    global HOSTS, UPLOAD_TIMESTAMP
    HOSTS.clear()
    UPLOAD_TIMESTAMP = None
    yield
    # Teardown: Clear global state after each test
    HOSTS.clear()
    UPLOAD_TIMESTAMP = None

# Mock AI services to prevent API calls during tests
@pytest.fixture(autouse=True)
def mock_ai_services():
    """Mock AI services to prevent API calls during tests"""
    with patch('main._generate_summary_text') as mock_generate:
        mock_generate.return_value = "Mock AI-generated summary for testing"
        yield mock_generate

# Test data
SAMPLE_HOSTS = [
    {
        "ip": "192.168.1.100",
        "location": {"country": "United States", "city": "New York"},
        "services": [{"port": 22, "service": "ssh", "product": "OpenSSH 8.2"}],
        "vulnerabilities": [{"id": "CVE-2021-44228", "severity": "Critical", "cvss_score": 10.0}],
        "threat_intelligence": {"security_labels": ["malware"], "risk_level": "High"}
    },
    {
        "ip": "10.0.0.50",
        "location": {"country": "Canada", "city": "Toronto"},
        "services": [{"port": 80, "service": "http", "product": "Apache 2.4"}],
        "vulnerabilities": [],
        "threat_intelligence": {"security_labels": [], "risk_level": "Low"}
    }
]

class TestHealthEndpoints:
    def test_root_endpoint(self):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "timestamp" in data

    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "hosts_loaded" in data

    def test_check_key_endpoint(self):
        response = client.get("/check_key/")
        assert response.status_code == 200
        data = response.json()
        assert "GEMINI_API_KEY" in data
        assert "OPENAI_API_KEY" in data
        assert "has_any_key" in data

class TestUploadEndpoint:
    def setup_method(self):
        # Reset global state before each test
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.clear()
        UPLOAD_TIMESTAMP = None
    
    def teardown_method(self):
        # Clean up after each test
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.clear()
        UPLOAD_TIMESTAMP = None

    def test_upload_valid_json_list(self):
        # Create a temporary JSON file
        test_data = SAMPLE_HOSTS
        json_content = json.dumps(test_data)
        
        response = client.post(
            "/upload_dataset/",
            files={"file": ("test.json", json_content, "application/json")}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["hosts_loaded"] == 2
        assert "upload_timestamp" in data
        assert "file_name" in data

    def test_upload_valid_json_object_with_hosts(self):
        test_data = {"hosts": SAMPLE_HOSTS}
        json_content = json.dumps(test_data)
        
        response = client.post(
            "/upload_dataset/",
            files={"file": ("test.json", json_content, "application/json")}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["hosts_loaded"] == 2

    def test_upload_invalid_json(self):
        response = client.post(
            "/upload_dataset/",
            files={"file": ("test.json", "invalid json", "application/json")}
        )
        
        assert response.status_code == 400
        assert "Invalid JSON" in response.json()["detail"]

    def test_upload_non_json_file(self):
        response = client.post(
            "/upload_dataset/",
            files={"file": ("test.txt", "not json content", "text/plain")}
        )
        
        assert response.status_code == 400
        assert "File must be a JSON file" in response.json()["detail"]

    def test_upload_empty_file(self):
        response = client.post(
            "/upload_dataset/",
            files={"file": ("test.json", "", "application/json")}
        )
        
        assert response.status_code == 400

    def test_upload_large_file(self):
        # Create a large JSON file (over 10MB)
        large_data = {"hosts": [{"ip": f"192.168.1.{i}"} for i in range(1000000)]}
        json_content = json.dumps(large_data)
        
        response = client.post(
            "/upload_dataset/",
            files={"file": ("large.json", json_content, "application/json")}
        )
        
        assert response.status_code == 400
        assert "File too large" in response.json()["detail"]

class TestSummarizeEndpoints:

    def test_summarize_host_success(self):
        # Set up test data
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.extend(SAMPLE_HOSTS)
        UPLOAD_TIMESTAMP = "2024-01-01T00:00:00"
        
        with patch('main._generate_summary_text') as mock_generate:
            mock_generate.return_value = "Test summary for 192.168.1.100"
            
            response = client.post("/summarize_host/", json={"ip": "192.168.1.100"})
            
            assert response.status_code == 200
            data = response.json()
            assert data["ip"] == "192.168.1.100"
            assert data["summary"] == "Test summary for 192.168.1.100"
            assert "location" in data
            assert "services" in data
            assert "vulnerabilities" in data
            assert "risk_level" in data

    def test_summarize_host_not_found(self):
        # Set up test data
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.extend(SAMPLE_HOSTS)
        UPLOAD_TIMESTAMP = "2024-01-01T00:00:00"
        
        response = client.post("/summarize_host/", json={"ip": "999.999.999.999"})
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_summarize_host_invalid_ip(self):
        response = client.post("/summarize_host/", json={"ip": ""})
        
        assert response.status_code == 422  # Validation error

    def test_summarize_all_success(self):
        # Set up test data
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.extend(SAMPLE_HOSTS)
        UPLOAD_TIMESTAMP = "2024-01-01T00:00:00"
        
        with patch('main._generate_summary_text') as mock_generate:
            mock_generate.return_value = "Test summary"
            
            response = client.get("/summarize_all/")
            
            assert response.status_code == 200
            data = response.json()
            assert "summaries" in data
            assert "total_hosts" in data
            assert "processing_time" in data
            assert len(data["summaries"]) == 2

class TestDataEndpoints:

    def test_get_uploaded_data_success(self):
        # Set up test data
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.extend(SAMPLE_HOSTS)
        UPLOAD_TIMESTAMP = "2024-01-01T00:00:00"
        
        response = client.get("/get_uploaded_data/")
        
        assert response.status_code == 200
        data = response.json()
        assert "hosts" in data
        assert "count" in data
        assert "upload_timestamp" in data
        assert data["count"] == 2

    def test_get_stats_success(self):
        # Set up test data
        global HOSTS, UPLOAD_TIMESTAMP
        HOSTS.extend(SAMPLE_HOSTS)
        UPLOAD_TIMESTAMP = "2024-01-01T00:00:00"
        
        response = client.get("/stats/")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_hosts" in data
        assert "risk_distribution" in data
        assert "avg_services_per_host" in data
        assert "avg_vulnerabilities_per_host" in data
        assert data["total_hosts"] == 2

class TestDataExtractionFunctions:
    
    def test_find_host_by_ip(self):
        from main import _find_host_by_ip
        
        # Set up test data
        global HOSTS
        HOSTS.extend(SAMPLE_HOSTS)
        
        # Test finding existing host
        host = _find_host_by_ip("192.168.1.100")
        assert host is not None
        assert host["ip"] == "192.168.1.100"
        
        # Test finding non-existing host
        host = _find_host_by_ip("999.999.999.999")
        assert host is None

    def test_extract_services(self):
        from main import _extract_services
        
        host = {
            "services": [
                {"port": 22, "service": "ssh", "product": "OpenSSH 8.2"},
                {"port": 80, "service": "http", "product": "Apache 2.4"}
            ]
        }
        
        services = _extract_services(host)
        assert len(services) == 2
        assert services[0]["port"] == 22
        assert services[0]["service"] == "ssh"
        assert services[1]["port"] == 80
        assert services[1]["service"] == "http"

    def test_extract_location(self):
        from main import _extract_location
        
        host = {
            "location": {
                "country": "United States",
                "city": "New York",
                "region": "NY"
            }
        }
        
        location = _extract_location(host)
        assert location["country"] == "United States"
        assert location["city"] == "New York"
        assert location["region"] == "NY"

    def test_extract_vulnerabilities(self):
        from main import _extract_vulns
        
        host = {
            "vulnerabilities": [
                {"id": "CVE-2021-44228", "severity": "Critical", "cvss_score": 10.0}
            ]
        }
        
        vulns = _extract_vulns(host)
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CVE-2021-44228"
        assert vulns[0]["severity"] == "Critical"
        assert vulns[0]["score"] == 10.0

    def test_compute_risk_with_reason(self):
        from main import _compute_risk_with_reason
        
        services = [{"port": 22}, {"port": 80}, {"port": 443}]
        vulnerabilities = [{"score": 9.0}]
        
        risk = _compute_risk_with_reason(services, vulnerabilities)
        assert "level" in risk
        assert "reason" in risk
        assert risk["level"] in ["Low", "Medium", "High", "Critical"]

class TestErrorHandling:
    def test_global_exception_handler(self):
        # This test would require mocking an endpoint to raise an exception
        # For now, we'll test that the handler exists
        from main import global_exception_handler
        assert callable(global_exception_handler)

    def test_invalid_endpoint(self):
        response = client.get("/nonexistent")
        assert response.status_code == 404

if __name__ == "__main__":
    pytest.main([__file__])
