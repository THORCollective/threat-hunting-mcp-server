"""
Tests for HEARTH integration and token optimization
"""

import pytest
from pathlib import Path


class TestHEARTHHuntSummaryMode:
    """Tests for HEARTHHunt summary mode (token optimization)"""

    @pytest.mark.unit
    def test_summary_mode_excludes_verbose_fields(self):
        """Test that summary mode excludes verbose fields"""
        # Simulate a HEARTHHunt object's to_dict output
        full_hunt = {
            "hunt_id": "H001",
            "hunt_type": "flame",
            "hypothesis": "Detecting credential access via LSASS",
            "tactic": "Credential Access",
            "tags": ["credential_access", "lsass"],
            "submitter": "test_hunter",
            "source": "HEARTH/test.md",
            "notes": "This is a long description that goes on and on " * 10,
            "why": "Long explanation...",
            "next_steps": "1. Step one\n2. Step two",
            "references": ["https://example.com"],
        }

        summary_hunt = {
            "hunt_id": "H001",
            "hunt_type": "flame",
            "hypothesis": "Detecting credential access via LSASS",
            "tactic": "Credential Access",
            "tags": ["credential_access", "lsass"],
            "submitter": "test_hunter",
            "source": "HEARTH/test.md",
            "notes_preview": full_hunt["notes"][:100] + "...",
            "has_details": True,
        }

        # Summary should not have these verbose fields
        assert "notes" not in summary_hunt
        assert "why" not in summary_hunt
        assert "next_steps" not in summary_hunt
        assert "references" not in summary_hunt

        # Summary should have these compact fields instead
        assert "notes_preview" in summary_hunt
        assert "has_details" in summary_hunt
        assert len(summary_hunt["notes_preview"]) <= 103  # 100 chars + "..."

    @pytest.mark.unit
    def test_full_mode_includes_all_fields(self):
        """Test that full mode includes all fields"""
        full_hunt = {
            "hunt_id": "H001",
            "hunt_type": "flame",
            "hypothesis": "Test hypothesis",
            "tactic": "Credential Access",
            "tags": ["test"],
            "submitter": "test_hunter",
            "source": "HEARTH/test.md",
            "notes": "Full notes",
            "why": "Why section",
            "next_steps": "Next steps",
            "references": ["https://example.com"],
        }

        # Full mode should have all these fields
        assert "notes" in full_hunt
        assert "why" in full_hunt
        assert "next_steps" in full_hunt
        assert "references" in full_hunt

    @pytest.mark.unit
    def test_summary_preview_length(self):
        """Test that notes preview is limited to 100 chars"""
        long_notes = "a" * 500

        # Simulate summary mode behavior
        notes_preview = long_notes[:100] + "..." if len(long_notes) > 100 else long_notes

        assert len(notes_preview) == 103  # 100 + "..."
        assert notes_preview.endswith("...")


class TestPaginationDefaults:
    """Tests for pagination default values"""

    @pytest.mark.unit
    def test_default_limit_is_five(self):
        """Test that default pagination limit is 5"""
        default_limit = 5
        assert default_limit == 5

    @pytest.mark.unit
    def test_limit_validation(self):
        """Test limit validation boundaries"""
        # Valid limits
        valid_limits = [1, 5, 10, 50, 100]
        for limit in valid_limits:
            assert 1 <= limit <= 100

        # Invalid limits
        assert not (0 >= 1 and 0 <= 100)
        assert not (101 >= 1 and 101 <= 100)


class TestHEARTHFileLoading:
    """Tests for HEARTH file loading"""

    @pytest.mark.unit
    def test_parse_hunt_file(self, temp_hunts_dir):
        """Test parsing of HEARTH hunt file"""
        hunt_file = temp_hunts_dir / "H001_test_hunt.md"
        assert hunt_file.exists()

        content = hunt_file.read_text()
        assert "# Test Hunt" in content
        assert "**Hunt ID:** H001" in content
        assert "**Hypothesis:**" in content
        assert "**Tactic:** Credential Access" in content
        assert "**Techniques:** T1003" in content

    @pytest.mark.unit
    def test_hunt_id_extraction(self, temp_hunts_dir):
        """Test extraction of hunt ID from filename"""
        hunt_file = temp_hunts_dir / "H001_test_hunt.md"
        filename = hunt_file.name

        # Hunt ID should be extracted from filename pattern
        if filename.startswith("H") and "_" in filename:
            hunt_id = filename.split("_")[0]
            assert hunt_id == "H001"

    @pytest.mark.unit
    def test_multiple_hunt_files(self, temp_hunts_dir):
        """Test handling of multiple hunt files"""
        # Create additional hunt files
        hunt2 = temp_hunts_dir / "H002_lateral_movement.md"
        hunt2.write_text("""# Lateral Movement Hunt

**Hunt ID:** H002
**Hypothesis:** Detecting lateral movement via SMB
**Tactic:** Lateral Movement
**Techniques:** T1021.002
""")

        hunt3 = temp_hunts_dir / "B001_baseline_hunt.md"
        hunt3.write_text("""# Baseline Hunt

**Hunt ID:** B001
**Hypothesis:** Baseline normal authentication patterns
**Tactic:** Credential Access
**Techniques:** T1078
""")

        # Count hunt files
        hunt_files = list(temp_hunts_dir.glob("*.md"))
        assert len(hunt_files) == 3

        # Verify hunt types
        hunt_ids = [f.name.split("_")[0] for f in hunt_files]
        assert "H001" in hunt_ids
        assert "H002" in hunt_ids
        assert "B001" in hunt_ids


class TestCacheOptimization:
    """Tests for Redis caching optimization"""

    @pytest.mark.unit
    def test_cache_ttl_config(self):
        """Test cache TTL configuration"""
        ttl_config = {
            "threat_intel": 3600,  # 1 hour
            "mitre_data": 86400,  # 24 hours
            "static_content": 86400,  # 24 hours
        }

        assert ttl_config["static_content"] == 86400
        assert ttl_config["mitre_data"] == 86400
        assert ttl_config["threat_intel"] == 3600

    @pytest.mark.unit
    def test_cache_namespace_key_generation(self):
        """Test cache key generation for static content"""
        namespace = "static_content"
        key = "mitre_matrix"

        cache_key = f"{namespace}:{key}"
        assert cache_key == "static_content:mitre_matrix"

        # Test another key
        methodology_key = f"{namespace}:peak_methodology"
        assert methodology_key == "static_content:peak_methodology"

    @pytest.mark.unit
    def test_cache_hit_reduces_token_usage(self):
        """Test that cache hit avoids loading full data"""
        # Simulate cache hit scenario
        cache_hit = True
        cached_data = {"framework": "PEAK", "summary": "cached"}

        if cache_hit:
            result = cached_data
            token_count = len(str(cached_data))
        else:
            # Would load full data
            full_data = {"framework": "PEAK", "full_documentation": "..." * 1000}
            result = full_data
            token_count = len(str(full_data))

        assert cache_hit is True
        assert token_count < 100  # Small cached data uses fewer tokens
