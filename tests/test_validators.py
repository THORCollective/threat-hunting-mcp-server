"""
Tests for Pydantic validation models
"""

import pytest
from pydantic import ValidationError

from models.validators import (
    AnalyzeAdversaryRequest,
    EnrichIOCRequest,
    ExecuteCustomQueryRequest,
    GetHuntsForTechniqueRequest,
    SearchCommunityHuntsRequest,
    format_validation_error,
)


class TestAnalyzeAdversaryRequest:
    """Tests for adversary ID validation"""

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_adversary_id(self):
        """Test valid MITRE Group ID formats"""
        valid_ids = ["G0001", "G0016", "G9999"]
        for adversary_id in valid_ids:
            request = AnalyzeAdversaryRequest(adversary_id=adversary_id)
            assert request.adversary_id == adversary_id

    @pytest.mark.unit
    @pytest.mark.validation
    def test_invalid_adversary_id(self):
        """Test invalid adversary ID formats are rejected"""
        invalid_ids = ["INVALID", "G001", "G00001", "T1003", ""]
        for adversary_id in invalid_ids:
            with pytest.raises(ValidationError) as exc_info:
                AnalyzeAdversaryRequest(adversary_id=adversary_id)
            assert "adversary_id" in str(exc_info.value)


class TestEnrichIOCRequest:
    """Tests for IOC validation"""

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_ip_address(self):
        """Test valid IP address IOC"""
        request = EnrichIOCRequest(ioc="192.168.1.1", ioc_type="ip")
        assert request.ioc == "192.168.1.1"
        assert request.ioc_type == "ip"

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_domain(self):
        """Test valid domain IOC"""
        request = EnrichIOCRequest(ioc="example.com", ioc_type="domain")
        assert request.ioc == "example.com"

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_hash(self):
        """Test valid hash IOC (MD5, SHA1, SHA256)"""
        valid_hashes = [
            "5d41402abc4b2a76b9719d911017c592",  # MD5
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",  # SHA1
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",  # SHA256
        ]
        for hash_value in valid_hashes:
            request = EnrichIOCRequest(ioc=hash_value, ioc_type="hash")
            assert request.ioc == hash_value

    @pytest.mark.unit
    @pytest.mark.validation
    def test_invalid_ioc_type(self):
        """Test invalid IOC type is rejected"""
        with pytest.raises(ValidationError):
            EnrichIOCRequest(ioc="test", ioc_type="invalid_type")


class TestExecuteCustomQueryRequest:
    """Tests for query validation"""

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_safe_query(self):
        """Test safe query is accepted"""
        request = ExecuteCustomQueryRequest(query="sourcetype=sysmon EventCode=1")
        assert "sourcetype" in request.query

    @pytest.mark.unit
    @pytest.mark.validation
    def test_dangerous_query_blocked(self):
        """Test dangerous query patterns are blocked"""
        dangerous_queries = [
            "index=main | delete",
            "index=main | drop",
            "index=main | outputlookup mode=append",
            "index=main | eval system(\"whoami\")",
        ]
        for query in dangerous_queries:
            with pytest.raises(ValidationError) as exc_info:
                ExecuteCustomQueryRequest(query=query)
            assert "dangerous" in str(exc_info.value).lower() or "blocked" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.validation
    def test_invalid_index_format(self):
        """Test invalid index format is rejected"""
        with pytest.raises(ValidationError):
            ExecuteCustomQueryRequest(query="test", index="invalid index!")


class TestSearchCommunityHuntsRequest:
    """Tests for search validation"""

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_limit(self):
        """Test valid limit values"""
        for limit in [1, 5, 10, 50, 100]:
            request = SearchCommunityHuntsRequest(limit=limit)
            assert request.limit == limit

    @pytest.mark.unit
    @pytest.mark.validation
    def test_limit_too_low(self):
        """Test limit below minimum is rejected"""
        with pytest.raises(ValidationError):
            SearchCommunityHuntsRequest(limit=0)

    @pytest.mark.unit
    @pytest.mark.validation
    def test_limit_too_high(self):
        """Test limit above maximum is rejected"""
        with pytest.raises(ValidationError):
            SearchCommunityHuntsRequest(limit=999)

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_hunt_types(self):
        """Test valid hunt type values"""
        valid_types = ["flame", "ember", "alchemy", "hypothesis", "baseline", "model"]
        for hunt_type in valid_types:
            request = SearchCommunityHuntsRequest(hunt_type=hunt_type)
            assert request.hunt_type == hunt_type.lower()

    @pytest.mark.unit
    @pytest.mark.validation
    def test_invalid_hunt_type(self):
        """Test invalid hunt type is rejected"""
        with pytest.raises(ValidationError):
            SearchCommunityHuntsRequest(hunt_type="invalid")

    @pytest.mark.unit
    @pytest.mark.validation
    def test_keyword_min_length(self):
        """Test keyword minimum length requirement"""
        # 2 chars is minimum
        request = SearchCommunityHuntsRequest(keyword="ab")
        assert request.keyword == "ab"

        # 1 char should fail
        with pytest.raises(ValidationError):
            SearchCommunityHuntsRequest(keyword="a")


class TestGetHuntsForTechniqueRequest:
    """Tests for technique ID validation"""

    @pytest.mark.unit
    @pytest.mark.validation
    def test_valid_technique_ids(self):
        """Test valid MITRE technique ID formats"""
        valid_ids = ["T1003", "T1003.001", "T9999.999"]
        for technique_id in valid_ids:
            request = GetHuntsForTechniqueRequest(technique_id=technique_id)
            assert request.technique_id == technique_id

    @pytest.mark.unit
    @pytest.mark.validation
    def test_invalid_technique_ids(self):
        """Test invalid technique ID formats are rejected"""
        invalid_ids = ["INVALID", "T001", "T10003", "G0016", "T1003.01"]
        for technique_id in invalid_ids:
            with pytest.raises(ValidationError) as exc_info:
                GetHuntsForTechniqueRequest(technique_id=technique_id)
            assert "technique" in str(exc_info.value).lower()


class TestFormatValidationError:
    """Tests for error formatting utility"""

    @pytest.mark.unit
    def test_format_validation_error(self):
        """Test validation error formatting"""
        try:
            AnalyzeAdversaryRequest(adversary_id="INVALID")
        except ValidationError as e:
            formatted = format_validation_error(e)

            assert formatted["status"] == "validation_error"
            assert "errors" in formatted
            assert len(formatted["errors"]) > 0
            assert "help" in formatted

            # Check error structure
            error = formatted["errors"][0]
            assert "field" in error
            assert "message" in error
            assert "type" in error
