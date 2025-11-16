"""
Pytest configuration and fixtures for threat_hunting_mcp tests
"""

import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def mock_settings():
    """Mock settings for testing"""
    from unittest.mock import Mock
    settings = Mock()
    settings.server_name = "threat-hunting-test"
    settings.hearth_path = None
    settings.hunts_directory = None
    settings.splunk_host = None
    settings.jwt_secret = "test-secret"
    settings.encryption_key = None
    settings.audit_log_path = "/tmp/audit.log"
    settings.redis_host = "localhost"
    settings.redis_port = 6379
    settings.redis_db = 0
    settings.redis_password = None
    return settings


@pytest.fixture
def temp_hunts_dir(tmp_path):
    """Create a temporary hunts directory for testing"""
    hunts_dir = tmp_path / "hunts"
    hunts_dir.mkdir()

    # Create a sample hunt file
    sample_hunt = hunts_dir / "H001_test_hunt.md"
    sample_hunt.write_text("""# Test Hunt

**Hunt ID:** H001
**Hypothesis:** Test hypothesis for credential access
**Tactic:** Credential Access
**Techniques:** T1003

## Why Hunt?
Test reasoning

## Next Steps
1. Investigate
2. Document
""")

    return hunts_dir
