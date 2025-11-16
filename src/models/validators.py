"""
Pydantic validation models for MCP tool inputs.

Provides input validation for all threat hunting tools to ensure:
- Security: Prevent injection attacks and malformed inputs
- UX: Clear, helpful error messages with examples
- Consistency: Standardized validation across all tools
"""

import re
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class MITRETactic(str, Enum):
    """Valid MITRE ATT&CK tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class HuntFramework(str, Enum):
    """Valid hunting frameworks"""
    PEAK = "PEAK"
    SQRRL = "SQRRL"
    INTELLIGENCE = "Intelligence"


class HuntType(str, Enum):
    """HEARTH hunt types"""
    FLAME = "flame"
    EMBER = "ember"
    ALCHEMY = "alchemy"
    HYPOTHESIS = "hypothesis"  # Alias for flame
    BASELINE = "baseline"  # Alias for ember
    MODEL = "model"  # Alias for alchemy


class IOCType(str, Enum):
    """Valid IOC types"""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"


# Validators

def validate_mitre_technique_id(value: str) -> str:
    """Validate MITRE ATT&CK technique ID format"""
    pattern = r'^T\d{4}(\.\d{3})?$'
    if not re.match(pattern, value):
        raise ValueError(
            f"Invalid MITRE technique ID format. Must match pattern T1234 or T1234.001. "
            f"Examples: T1003, T1003.001, T1078. Got: {value}"
        )
    return value


def validate_limit(value: int) -> int:
    """Validate limit parameter is within reasonable bounds"""
    if value < 1:
        raise ValueError("Limit must be at least 1")
    if value > 100:
        raise ValueError("Limit cannot exceed 100 (use pagination for larger result sets)")
    return value


def validate_non_empty_string(value: str, field_name: str = "field") -> str:
    """Validate string is not empty or whitespace"""
    if not value or not value.strip():
        raise ValueError(f"{field_name} cannot be empty or whitespace")
    return value.strip()


# Request Models

class CreateBehavioralHuntRequest(BaseModel):
    """Validation for create_behavioral_hunt tool"""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID (e.g., T1003.001)")
    technique_name: str = Field(..., min_length=1, max_length=200, description="Name of the technique")
    tactic: str = Field(..., description="MITRE ATT&CK tactic")
    hypothesis: str = Field(..., min_length=10, max_length=2000, description="Hunt hypothesis statement")
    hunter_name: str = Field(..., min_length=1, max_length=100, description="Name of the threat hunter")
    location: str = Field(..., min_length=1, max_length=200, description="Where to hunt")
    data_sources: List[dict] = Field(..., min_items=1, description="List of data sources")
    actor: Optional[str] = Field(None, max_length=100, description="Optional threat actor")
    threat_intel_sources: Optional[List[str]] = Field(None, description="Optional threat intel sources")
    related_tickets: Optional[dict] = Field(None, description="Optional related tickets")

    @field_validator('technique_id')
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        return validate_mitre_technique_id(v)

    @field_validator('tactic')
    @classmethod
    def validate_tactic(cls, v: str) -> str:
        # Try to match to known tactics (case-insensitive)
        tactic_map = {t.value.lower(): t.value for t in MITRETactic}
        v_lower = v.lower()
        if v_lower in tactic_map:
            return tactic_map[v_lower]
        # If not exact match, return as-is but log warning
        return v

    @field_validator('technique_name', 'hunter_name', 'location')
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        return validate_non_empty_string(v)


class SearchCommunityHuntsRequest(BaseModel):
    """Validation for search_community_hunts tool"""
    tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic filter")
    tags: Optional[List[str]] = Field(None, description="Tag filters")
    keyword: Optional[str] = Field(None, min_length=2, max_length=200, description="Search keyword")
    hunt_type: Optional[str] = Field(None, description="Hunt type filter")
    limit: int = Field(5, ge=1, le=100, description="Maximum results (1-100)")

    @field_validator('hunt_type')
    @classmethod
    def validate_hunt_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Normalize to lowercase for comparison
        v_lower = v.lower()
        valid_types = [ht.value for ht in HuntType]
        if v_lower not in valid_types:
            raise ValueError(
                f"Invalid hunt_type. Must be one of: {', '.join(valid_types)}. Got: {v}"
            )
        return v_lower


class AnalyzeAdversaryRequest(BaseModel):
    """Validation for analyze_adversary tool"""
    adversary_id: str = Field(..., description="MITRE ATT&CK Group ID (e.g., G0016)")

    @field_validator('adversary_id')
    @classmethod
    def validate_adversary_id(cls, v: str) -> str:
        # MITRE group IDs are G followed by 4 digits
        pattern = r'^G\d{4}$'
        if not re.match(pattern, v):
            raise ValueError(
                f"Invalid adversary ID format. Must match pattern G#### (e.g., G0016). Got: {v}"
            )
        return v


class ExecuteCustomQueryRequest(BaseModel):
    """Validation for execute_custom_query tool"""
    query: str = Field(..., min_length=1, max_length=5000, description="SPL query to execute")
    index: str = Field("*", max_length=100, description="Splunk index to search")

    @field_validator('query')
    @classmethod
    def validate_query(cls, v: str) -> str:
        # Basic security validation - prevent obvious injection attempts
        dangerous_patterns = [
            r'\|\s*delete',
            r'\|\s*drop',
            r'\|\s*outputlookup.*mode\s*=\s*append',  # Prevent data modification
            r'eval.*system\(',  # Prevent command execution
        ]

        v_lower = v.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, v_lower):
                raise ValueError(
                    f"Query contains potentially dangerous pattern and has been blocked for security. "
                    f"Please use read-only search commands only."
                )

        return validate_non_empty_string(v, "query")

    @field_validator('index')
    @classmethod
    def validate_index(cls, v: str) -> str:
        # Index names should be alphanumeric with limited special chars
        if not re.match(r'^[\w\-\*]+$', v):
            raise ValueError(
                f"Invalid index format. Must contain only letters, numbers, hyphens, underscores, and asterisk. Got: {v}"
            )
        return v


class EnrichIOCRequest(BaseModel):
    """Validation for enrich_ioc tool"""
    ioc: str = Field(..., min_length=1, max_length=500, description="Indicator of Compromise")
    ioc_type: str = Field(..., description="Type of IOC")

    @field_validator('ioc_type')
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        v_lower = v.lower()
        valid_types = [t.value for t in IOCType]
        if v_lower not in valid_types:
            raise ValueError(
                f"Invalid ioc_type. Must be one of: {', '.join(valid_types)}. Got: {v}"
            )
        return v_lower

    @field_validator('ioc')
    @classmethod
    def validate_ioc_format(cls, v: str, info) -> str:
        """Basic format validation based on IOC type"""
        ioc_type = info.data.get('ioc_type', '').lower()

        # IP address validation
        if ioc_type == 'ip':
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if not re.match(ip_pattern, v):
                raise ValueError(f"Invalid IP address format. Example: 192.168.1.1")

        # Domain validation
        elif ioc_type == 'domain':
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, v):
                raise ValueError(f"Invalid domain format. Example: example.com")

        # Hash validation (MD5, SHA1, SHA256)
        elif ioc_type == 'hash':
            hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
            if not re.match(hash_pattern, v):
                raise ValueError(
                    f"Invalid hash format. Must be MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex)"
                )

        return v


class CreateBaselineRequest(BaseModel):
    """Validation for create_baseline tool"""
    environment: str = Field(..., min_length=1, max_length=100, description="Environment to baseline")
    metrics: List[str] = Field(..., min_items=1, max_items=50, description="Metrics to baseline")

    @field_validator('environment')
    @classmethod
    def validate_environment(cls, v: str) -> str:
        return validate_non_empty_string(v, "environment")

    @field_validator('metrics')
    @classmethod
    def validate_metrics(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one metric must be specified")
        # Validate each metric is non-empty
        return [validate_non_empty_string(m, "metric") for m in v]


class AnalyzeWithMLRequest(BaseModel):
    """Validation for analyze_with_ml tool"""
    data_source: str = Field(..., min_length=1, max_length=200, description="Data source to analyze")
    algorithm: str = Field("isolation_forest", description="ML algorithm to use")

    @field_validator('algorithm')
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        valid_algorithms = ['isolation_forest', 'kmeans', 'dbscan', 'autoencoder']
        if v.lower() not in valid_algorithms:
            raise ValueError(
                f"Invalid algorithm. Must be one of: {', '.join(valid_algorithms)}. Got: {v}"
            )
        return v.lower()


class GetHuntsForTacticRequest(BaseModel):
    """Validation for get_hunts_for_tactic tool"""
    tactic: str = Field(..., description="MITRE ATT&CK tactic name")
    limit: int = Field(5, ge=1, le=100, description="Maximum results (1-100)")

    @field_validator('tactic')
    @classmethod
    def validate_tactic(cls, v: str) -> str:
        return validate_non_empty_string(v, "tactic")


class GetHuntsForTechniqueRequest(BaseModel):
    """Validation for get_hunts_for_technique tool"""
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")

    @field_validator('technique_id')
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        return validate_mitre_technique_id(v)


# Utility function to format validation errors for user-friendly display

def format_validation_error(error) -> dict:
    """
    Format Pydantic ValidationError into user-friendly error response

    Args:
        error: Pydantic ValidationError

    Returns:
        Dictionary with status, errors, and help message
    """
    errors = []
    for err in error.errors():
        field = err['loc'][0] if err['loc'] else 'unknown'
        message = err['msg']

        # Make error messages more user-friendly
        if 'String should match pattern' in message:
            message = "Invalid format - see examples for correct format"
        elif 'Input should be less than or equal to' in message:
            message = f"Value too large - {message.split('<=')[1].strip() if '<=' in message else 'maximum exceeded'}"
        elif 'Input should be greater than or equal to' in message:
            message = f"Value too small - {message.split('>=')[1].strip() if '>=' in message else 'minimum not met'}"

        errors.append({
            "field": field,
            "message": message,
            "type": err['type']
        })

    return {
        "status": "validation_error",
        "errors": errors,
        "help": "Check the error messages above and correct your inputs. See tool documentation for examples."
    }
