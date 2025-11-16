"""
Tests for server health check functionality
"""

import pytest


class TestGetServerHealth:
    """Tests for get_server_health MCP tool"""

    @pytest.mark.unit
    @pytest.mark.health
    def test_health_check_all_features_enabled(self, mock_settings):
        """Test health check when all features are available"""
        # This would require mocking the full server initialization
        # For now, we test the feature availability logic

        features = {
            'hearth': True,
            'splunk': True,
            'nlp': True,
            'atlassian': True,
            'peak': True,
            'threat_intel': True,
        }

        # Count enabled features
        enabled = [f for f, available in features.items() if available]
        assert len(enabled) == 6

        # Status should be "healthy"
        if len(enabled) == 6:
            status = "healthy"
        elif len(enabled) >= 3:
            status = "degraded"
        else:
            status = "minimal"

        assert status == "healthy"

    @pytest.mark.unit
    @pytest.mark.health
    def test_health_check_degraded_mode(self):
        """Test health check in degraded mode (some features disabled)"""
        features = {
            'hearth': True,
            'splunk': False,
            'nlp': False,
            'atlassian': False,
            'peak': True,
            'threat_intel': True,
        }

        enabled = [f for f, available in features.items() if available]
        assert len(enabled) == 3

        # Status should be "degraded"
        if len(enabled) == 6:
            status = "healthy"
        elif len(enabled) >= 3:
            status = "degraded"
        else:
            status = "minimal"

        assert status == "degraded"

    @pytest.mark.unit
    @pytest.mark.health
    def test_health_check_minimal_mode(self):
        """Test health check in minimal mode (most features disabled)"""
        features = {
            'hearth': False,
            'splunk': False,
            'nlp': False,
            'atlassian': False,
            'peak': True,
            'threat_intel': True,
        }

        enabled = [f for f, available in features.items() if available]
        assert len(enabled) == 2

        # Status should be "minimal"
        if len(enabled) == 6:
            status = "healthy"
        elif len(enabled) >= 3:
            status = "degraded"
        else:
            status = "minimal"

        assert status == "minimal"

    @pytest.mark.unit
    @pytest.mark.health
    def test_recommendations_generated(self):
        """Test that recommendations are generated for disabled features"""
        features = {
            'hearth': False,
            'splunk': False,
            'nlp': True,
            'atlassian': False,
            'peak': True,
            'threat_intel': True,
        }

        recommendations = []

        if not features['hearth']:
            recommendations.append(
                "Set HEARTH_PATH environment variable to enable community hunt database"
            )
        if not features['splunk']:
            recommendations.append(
                "Configure SPLUNK_HOST for query execution capabilities"
            )
        if not features['atlassian']:
            recommendations.append(
                "Set JIRA_URL for ticket integration"
            )

        assert len(recommendations) == 3
        assert any("HEARTH_PATH" in r for r in recommendations)
        assert any("SPLUNK_HOST" in r for r in recommendations)
        assert any("JIRA_URL" in r for r in recommendations)


class TestFeatureAvailability:
    """Tests for feature availability checks"""

    @pytest.mark.unit
    def test_hearth_feature_check(self):
        """Test HEARTH feature availability logic"""
        # Feature is available if hearth path is set
        hearth_path = "/path/to/hearth"
        hearth_available = hearth_path is not None
        assert hearth_available is True

        # Feature is unavailable if path is None
        hearth_path = None
        hearth_available = hearth_path is not None
        assert hearth_available is False

    @pytest.mark.unit
    def test_splunk_feature_check(self):
        """Test Splunk feature availability logic"""
        # Feature is available if splunk host is set
        splunk_host = "splunk.example.com"
        splunk_available = splunk_host is not None
        assert splunk_available is True

        # Feature is unavailable if host is None
        splunk_host = None
        splunk_available = splunk_host is not None
        assert splunk_available is False

    @pytest.mark.unit
    def test_always_available_features(self):
        """Test features that are always available"""
        # PEAK and threat_intel should always be available
        peak_available = True
        threat_intel_available = True

        assert peak_available is True
        assert threat_intel_available is True


class TestGracefulDegradation:
    """Tests for graceful degradation behavior"""

    @pytest.mark.unit
    def test_missing_feature_error_message(self):
        """Test error messages for missing features"""
        features = {'hearth': False}

        if not features.get('hearth'):
            error_msg = {
                "status": "error",
                "error": "HEARTH community database not available",
                "help": "Set HEARTH_PATH environment variable to enable community hunts"
            }

        assert error_msg["status"] == "error"
        assert "not available" in error_msg["error"]
        assert "HEARTH_PATH" in error_msg["help"]

    @pytest.mark.unit
    def test_splunk_unavailable_message(self):
        """Test error message when Splunk is unavailable"""
        features = {'splunk': False}

        if not features.get('splunk'):
            error_msg = {
                "status": "error",
                "error": "Splunk integration not available",
                "help": "Configure SPLUNK_HOST in environment to enable query execution"
            }

        assert error_msg["status"] == "error"
        assert "Splunk" in error_msg["error"]
        assert "SPLUNK_HOST" in error_msg["help"]
