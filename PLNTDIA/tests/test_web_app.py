"""
Tests for PLNTDIA Web API

Tests cover:
- API endpoints functionality
- Pagination
- Input validation
- Error handling
"""

import pytest
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_app import app, _data_cache, ValidationError, validate_pagination, validate_severity, validate_environment, validate_date, paginate


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset cache before each test."""
    _data_cache["servers"] = None
    _data_cache["workers"] = None
    _data_cache["cves"] = None
    _data_cache["availability_manager"] = None
    _data_cache["last_load"] = None


# ============================================================
# VALIDATION HELPER TESTS
# ============================================================

class TestValidationHelpers:
    """Test validation helper functions."""
    
    def test_validate_pagination_defaults(self):
        """Test pagination with default values."""
        page, per_page = validate_pagination(None, None)
        assert page == 1
        assert per_page == 20
    
    def test_validate_pagination_custom(self):
        """Test pagination with custom values."""
        page, per_page = validate_pagination("2", "50")
        assert page == 2
        assert per_page == 50
    
    def test_validate_pagination_invalid_page(self):
        """Test pagination with invalid page."""
        with pytest.raises(ValidationError) as exc_info:
            validate_pagination("0", "20")
        assert "page must be >= 1" in str(exc_info.value.message)
    
    def test_validate_pagination_invalid_per_page(self):
        """Test pagination with invalid per_page."""
        with pytest.raises(ValidationError) as exc_info:
            validate_pagination("1", "500")
        assert "per_page must be between" in str(exc_info.value.message)
    
    def test_validate_pagination_non_integer(self):
        """Test pagination with non-integer values."""
        with pytest.raises(ValidationError) as exc_info:
            validate_pagination("abc", "20")
        assert "must be integers" in str(exc_info.value.message)
    
    def test_validate_severity_valid(self):
        """Test valid severity values."""
        assert validate_severity("Critical") == "critical"
        assert validate_severity("HIGH") == "high"
        assert validate_severity("medium") == "medium"
        assert validate_severity("Low") == "low"
    
    def test_validate_severity_invalid(self):
        """Test invalid severity value."""
        with pytest.raises(ValidationError) as exc_info:
            validate_severity("invalid")
        assert "Invalid severity" in str(exc_info.value.message)
    
    def test_validate_severity_none(self):
        """Test None severity."""
        assert validate_severity(None) is None
    
    def test_validate_environment_valid(self):
        """Test valid environment values."""
        assert validate_environment("dev") == "DEV"
        assert validate_environment("TEST") == "TEST"
        assert validate_environment("Prod") == "PROD"
    
    def test_validate_environment_invalid(self):
        """Test invalid environment value."""
        with pytest.raises(ValidationError) as exc_info:
            validate_environment("staging")
        assert "Invalid environment" in str(exc_info.value.message)
    
    def test_validate_date_valid(self):
        """Test valid date format."""
        from datetime import date
        result = validate_date("2025-12-25", "start_date")
        assert result == date(2025, 12, 25)
    
    def test_validate_date_invalid(self):
        """Test invalid date format."""
        with pytest.raises(ValidationError) as exc_info:
            validate_date("25-12-2025", "start_date")
        assert "YYYY-MM-DD format" in str(exc_info.value.message)
    
    def test_paginate_first_page(self):
        """Test pagination - first page."""
        items = list(range(100))
        result = paginate(items, page=1, per_page=20)
        
        assert len(result["items"]) == 20
        assert result["items"] == list(range(20))
        assert result["pagination"]["page"] == 1
        assert result["pagination"]["total"] == 100
        assert result["pagination"]["total_pages"] == 5
        assert result["pagination"]["has_next"] is True
        assert result["pagination"]["has_prev"] is False
    
    def test_paginate_middle_page(self):
        """Test pagination - middle page."""
        items = list(range(100))
        result = paginate(items, page=3, per_page=20)
        
        assert len(result["items"]) == 20
        assert result["items"] == list(range(40, 60))
        assert result["pagination"]["has_next"] is True
        assert result["pagination"]["has_prev"] is True
    
    def test_paginate_last_page(self):
        """Test pagination - last page."""
        items = list(range(95))
        result = paginate(items, page=5, per_page=20)
        
        assert len(result["items"]) == 15  # Only 15 items on last page
        assert result["pagination"]["has_next"] is False
        assert result["pagination"]["has_prev"] is True


# ============================================================
# API ENDPOINT TESTS
# ============================================================

class TestStatusEndpoint:
    """Test /api/status endpoint."""
    
    def test_status_ok(self, client):
        """Test health check endpoint."""
        response = client.get('/api/status')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data["status"] == "ok"
        assert "timestamp" in data


class TestHealthEndpoint:
    """Test /api/health endpoint."""
    
    def test_health_returns_status(self, client):
        """Test health endpoint returns overall status."""
        response = client.get('/api/health')
        assert response.status_code in [200, 503]
        
        data = json.loads(response.data)
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
    
    def test_health_includes_components(self, client):
        """Test health endpoint includes component statuses."""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert "components" in data
        assert "timestamp" in data
        assert "version" in data
    
    def test_health_checks_data_cache(self, client):
        """Test health endpoint checks data cache component."""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert "data_cache" in data["components"]
        assert "status" in data["components"]["data_cache"]
    
    def test_health_checks_csv_files(self, client):
        """Test health endpoint checks CSV files component."""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert "csv_files" in data["components"]
        assert "status" in data["components"]["csv_files"]


class TestMetricsEndpoint:
    """Test /api/metrics endpoint."""
    
    def test_metrics_returns_totals(self, client):
        """Test metrics endpoint returns totals."""
        response = client.get('/api/metrics')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "totals" in data
        assert "servers" in data["totals"]
        assert "cves" in data["totals"]
        assert "workers" in data["totals"]
    
    def test_metrics_returns_distributions(self, client):
        """Test metrics endpoint returns distributions."""
        response = client.get('/api/metrics')
        data = json.loads(response.data)
        
        assert "distributions" in data
        assert "cves_by_severity" in data["distributions"]
        assert "servers_by_environment" in data["distributions"]
        assert "workers_by_level" in data["distributions"]
    
    def test_metrics_severity_distribution(self, client):
        """Test metrics has all severity levels."""
        response = client.get('/api/metrics')
        data = json.loads(response.data)
        
        severity_dist = data["distributions"]["cves_by_severity"]
        assert "Critical" in severity_dist
        assert "High" in severity_dist
        assert "Medium" in severity_dist
        assert "Low" in severity_dist
    
    def test_metrics_includes_cache_info(self, client):
        """Test metrics includes cache information."""
        response = client.get('/api/metrics')
        data = json.loads(response.data)
        
        assert "cache" in data
        assert "is_loaded" in data["cache"]


class TestServersEndpoint:
    """Test /api/servers endpoint."""
    
    def test_get_servers(self, client):
        """Test getting all servers."""
        response = client.get('/api/servers')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "servers" in data
        assert "count" in data
        assert "pagination" in data
    
    def test_get_servers_with_pagination(self, client):
        """Test servers with pagination."""
        response = client.get('/api/servers?page=1&per_page=10')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data["servers"]) <= 10
        assert data["pagination"]["per_page"] == 10
    
    def test_get_servers_filter_environment(self, client):
        """Test filtering servers by environment."""
        response = client.get('/api/servers?environment=dev')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        for server in data["servers"]:
            assert server["environment"] == "DEV"
    
    def test_get_servers_invalid_environment(self, client):
        """Test invalid environment filter."""
        response = client.get('/api/servers?environment=invalid')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert "error" in data
    
    def test_get_servers_invalid_pagination(self, client):
        """Test invalid pagination parameters."""
        response = client.get('/api/servers?page=0')
        assert response.status_code == 400


class TestCVEsEndpoint:
    """Test /api/cves endpoint."""
    
    def test_get_cves(self, client):
        """Test getting all CVEs."""
        response = client.get('/api/cves')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "cves" in data
        assert "count" in data
        assert "pagination" in data
    
    def test_get_cves_with_pagination(self, client):
        """Test CVEs with pagination."""
        response = client.get('/api/cves?page=1&per_page=5')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data["cves"]) <= 5
    
    def test_get_cves_filter_severity(self, client):
        """Test filtering CVEs by severity."""
        response = client.get('/api/cves?severity=critical')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        for cve in data["cves"]:
            assert cve["severity"].lower() == "critical"
    
    def test_get_cves_invalid_severity(self, client):
        """Test invalid severity filter."""
        response = client.get('/api/cves?severity=super_critical')
        assert response.status_code == 400
    
    def test_get_cves_sort_by_epss(self, client):
        """Test sorting CVEs by EPSS score."""
        response = client.get('/api/cves?sort=epss&per_page=10')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        if len(data["cves"]) > 1:
            # Check descending order
            for i in range(len(data["cves"]) - 1):
                assert data["cves"][i]["epss_score"] >= data["cves"][i + 1]["epss_score"]
    
    def test_get_cves_invalid_sort(self, client):
        """Test invalid sort parameter."""
        response = client.get('/api/cves?sort=invalid')
        assert response.status_code == 400


class TestWorkersEndpoint:
    """Test /api/workers endpoint."""
    
    def test_get_workers(self, client):
        """Test getting all workers."""
        response = client.get('/api/workers')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "workers" in data
        assert "count" in data
    
    def test_get_workers_filter_level(self, client):
        """Test filtering workers by level."""
        response = client.get('/api/workers?level=senior')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        for worker in data["workers"]:
            assert worker["level"].lower() == "senior"


class TestHolidaysEndpoint:
    """Test /api/holidays endpoint."""
    
    def test_get_holidays(self, client):
        """Test getting all holidays."""
        response = client.get('/api/holidays')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "holidays" in data
        assert "count" in data


class TestStatsEndpoint:
    """Test /api/stats endpoint."""
    
    def test_get_stats(self, client):
        """Test getting stats."""
        response = client.get('/api/stats')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "total_servers" in data
        assert "total_cves" in data
        assert "total_workers" in data
        assert "servers_by_environment" in data
        assert "cves_by_severity" in data


class TestCVEDetailEndpoint:
    """Test /api/cves/<cve_id> endpoint."""
    
    def test_get_cve_not_found(self, client):
        """Test getting non-existent CVE."""
        response = client.get('/api/cves/CVE-DOES-NOT-EXIST')
        assert response.status_code == 404


class TestServerDetailEndpoint:
    """Test /api/servers/<server_id> endpoint."""
    
    def test_get_server_not_found(self, client):
        """Test getting non-existent server."""
        response = client.get('/api/servers/SERVER-DOES-NOT-EXIST')
        assert response.status_code == 404


# ============================================================
# ERROR HANDLING TESTS
# ============================================================

class TestErrorHandling:
    """Test error handling."""
    
    def test_404_handler(self, client):
        """Test 404 error handler."""
        response = client.get('/api/nonexistent')
        assert response.status_code == 404
    
    def test_validation_error_response(self, client):
        """Test validation error response format."""
        response = client.get('/api/servers?page=-1')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert "error" in data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
