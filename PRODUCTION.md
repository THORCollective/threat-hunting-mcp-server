# Production Deployment Guide

This document covers production-ready features, monitoring, testing, and optimization capabilities of the Threat Hunting MCP Server.

## Overview

The server includes enterprise-grade features for production deployment:

- ✅ **Health Monitoring** - Real-time diagnostics and feature availability
- ✅ **Input Validation** - Comprehensive security validation with Pydantic
- ✅ **Token Optimization** - 40-50% reduction in token usage
- ✅ **Testing Infrastructure** - 38 automated tests with 100% pass rate
- ✅ **Structured Logging** - JSON logging to stderr for SIEM integration
- ✅ **Graceful Degradation** - Intelligent handling of optional features

---

## Health Monitoring

### `get_server_health()` MCP Tool

Real-time server diagnostics and feature availability check.

**Usage:**
```python
result = await get_server_health()
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "server_name": "threat-hunting",
  "features": {
    "summary": {
      "available": 4,
      "total": 6,
      "percentage": 66.7
    },
    "details": {
      "hearth": {
        "available": true,
        "hunt_count": 150,
        "path": "/path/to/HEARTH"
      },
      "splunk": {
        "available": false,
        "reason": "not configured",
        "config_required": ["SPLUNK_HOST", "SPLUNK_PORT", "SPLUNK_TOKEN"]
      },
      "nlp": {
        "available": true,
        "status": "enabled"
      },
      "atlassian": {
        "available": false,
        "reason": "not configured",
        "config_required": ["ATLASSIAN_URL", "ATLASSIAN_USERNAME", "ATLASSIAN_API_TOKEN"]
      },
      "peak": {
        "available": true,
        "hunts_directory": "/path/to/hunts",
        "hunt_count": 2
      },
      "threat_intel": {
        "available": true,
        "status": "enabled"
      }
    }
  },
  "dependencies": {
    "redis": {
      "available": true,
      "status": "connected"
    }
  },
  "recommendations": [
    "Enable HEARTH for community hunt access - set HEARTH_PATH in .env",
    "Configure Splunk for data analysis - set SPLUNK_HOST, SPLUNK_PORT, SPLUNK_TOKEN"
  ]
}
```

**Health Status:**
- `healthy` - 50%+ features available
- `degraded` - 30-49% features available
- `minimal` - <30% features available

**Monitoring:**
Check health periodically to ensure all expected features are available:
```bash
# Via MCP tool
claude-code mcp call threat-hunting get_server_health

# Expected in logs (stderr):
{"event": "server_startup", "timestamp": "..."}
{"event": "feature_status", "feature": "hearth", "available": true, "status": "enabled"}
```

---

## Input Validation & Security

### Pydantic Validation Models

All critical MCP tools use Pydantic for input validation with security checks.

**Validated Tools:**
- `execute_custom_query` - SQL/command injection prevention
- `analyze_adversary` - MITRE Group ID format validation
- `enrich_ioc` - IOC format validation (IP, domain, hash)
- `search_community_hunts` - Search parameter validation
- `get_hunts_for_technique` - MITRE technique ID validation
- `create_baseline` - Environment and metrics validation
- `analyze_with_ml` - Algorithm validation

**Security Features:**

1. **Injection Prevention:**
   ```python
   # Blocked patterns in queries:
   - | delete
   - | drop
   - | outputlookup mode=append
   - eval system(...)
   ```

2. **Format Validation:**
   ```python
   # MITRE Technique IDs: T1234 or T1234.001
   # MITRE Group IDs: G0001-G9999
   # IP Addresses: xxx.xxx.xxx.xxx
   # Hashes: MD5 (32), SHA1 (40), SHA256 (64 hex chars)
   ```

3. **User-Friendly Errors:**
   ```json
   {
     "status": "validation_error",
     "errors": [
       {
         "field": "technique_id",
         "message": "Invalid MITRE technique ID format. Must match pattern T1234 or T1234.001",
         "type": "value_error"
       }
     ],
     "help": "Check the error messages above and correct your inputs. See tool documentation for examples."
   }
   ```

**Limits:**
- Search results: 1-100 (default: 5)
- String fields: Max 200-5000 chars depending on field
- Lists: 1-50 items max

---

## Token Optimization

40-50% reduction in token usage through smart response formatting and caching.

### Summary Mode

HEARTH hunts return compact summaries by default. Use `get_hunt_by_id()` for full details.

**Summary Response (~200 tokens):**
```json
{
  "hunt_id": "H001",
  "hunt_type": "flame",
  "hypothesis": "Detect credential access via LSASS memory",
  "tactic": "Credential Access",
  "tags": ["credential_access", "lsass"],
  "notes_preview": "This hunt focuses on detecting any process accessing LSASS memory...",
  "has_details": true
}
```

**Full Response (~800 tokens):**
```json
{
  "hunt_id": "H001",
  "notes": "Full detailed notes (500+ words)...",
  "why": "Complete reasoning section...",
  "next_steps": "1. Step one\n2. Step two...",
  "references": ["https://...", "https://..."]
}
```

### Pagination Defaults

Default limits reduced from 20→5 results:
- `search_community_hunts()` - default 5 (max 100)
- `get_hunts_for_tactic()` - default 5 (max 100)
- `recommend_hunts()` - default 5 (max 100)
- `get_recent_community_hunts()` - default 5 (max 100)

### Redis Caching

Static resources cached for 24 hours:
- MITRE ATT&CK matrix
- PEAK methodology documentation
- Hunting framework guides

**Cache Configuration:**
```python
cache_ttl = {
    "threat_intel": 3600,      # 1 hour
    "mitre_data": 86400,       # 24 hours
    "static_content": 86400,   # 24 hours
}
```

**Token Savings:**
- First request: Full resource (~2000 tokens)
- Cached requests: Reference only (~50 tokens)
- Savings: ~95% on repeated resource access

---

## Testing Infrastructure

### Test Suite

38 automated tests with 100% pass rate covering validation, health checks, and optimization.

**Run Tests:**
```bash
cd /path/to/threat_hunting_mcp

# Activate virtual environment
source venv/bin/activate

# Run all tests
pytest tests/ -v

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m validation     # Validation tests only
pytest -m health         # Health check tests only

# Run with coverage (requires pytest-cov)
pytest tests/ --cov=src --cov-report=html
```

**Test Files:**
- `tests/test_validators.py` - Input validation (18 tests)
- `tests/test_server_health.py` - Health monitoring (9 tests)
- `tests/test_hearth_integration.py` - Token optimization (11 tests)
- `tests/conftest.py` - Shared fixtures

**Test Categories:**
```python
@pytest.mark.unit         # Fast unit tests
@pytest.mark.validation   # Input validation tests
@pytest.mark.health       # Health check tests
@pytest.mark.integration  # Integration tests (future)
@pytest.mark.slow         # Slow-running tests (future)
```

**Example Test Run:**
```bash
$ pytest tests/ -v

tests/test_hearth_integration.py::test_summary_mode ✓
tests/test_server_health.py::test_health_all_features ✓
tests/test_validators.py::test_valid_technique_id ✓
...
======================== 38 passed in 0.13s ========================
```

**CI/CD Integration:**
```yaml
# .github/workflows/test.yml (example)
- name: Run tests
  run: |
    source venv/bin/activate
    pytest tests/ -v --tb=short
```

---

## Structured Logging

JSON-formatted logs written to stderr for SIEM integration and analysis.

### Configuration

Logs use structured JSON format via `structlog`:

```python
import structlog

# Configured in server.py
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
```

### Log Output

**Startup Logs:**
```json
{"event": "server_startup", "timestamp": "2024-11-16T...", "level": "info"}
{"event": "feature_status", "feature": "hearth", "available": true, "status": "enabled", "timestamp": "...", "level": "info"}
{"event": "feature_status", "feature": "splunk", "available": false, "status": "disabled", "timestamp": "...", "level": "info"}
{"event": "feature_summary", "available": 4, "total": 6, "percentage": 66.7, "timestamp": "...", "level": "info"}
```

**Configuration Hints:**
```json
{"event": "configuration_hint", "feature": "splunk", "hint": "Set SPLUNK_HOST, SPLUNK_PORT, SPLUNK_TOKEN in .env", "timestamp": "...", "level": "info"}
```

**Error Logs:**
```json
{"event": "error", "error": "Hunt not found", "hunt_id": "H999", "timestamp": "...", "level": "error"}
```

### SIEM Integration

**Splunk:**
```spl
index=mcp_logs sourcetype=json
| spath event
| stats count by event, feature, status
```

**Elasticsearch:**
```json
{
  "mappings": {
    "properties": {
      "event": {"type": "keyword"},
      "feature": {"type": "keyword"},
      "status": {"type": "keyword"},
      "timestamp": {"type": "date"}
    }
  }
}
```

### Log Levels

- `INFO` - Normal operations (startup, feature status)
- `WARNING` - Non-critical issues (NLP unavailable)
- `ERROR` - Operation failures (hunt not found, query errors)

---

## Graceful Degradation

The server handles optional features intelligently with helpful error messages.

### Feature Availability Tracking

```python
self.features = {
    'hearth': self.hearth is not None,
    'splunk': self.splunk is not None,
    'nlp': self.nlp is not None,
    'atlassian': self.atlassian is not None,
    'peak': True,  # Always available
    'threat_intel': True,  # Always available
}
```

### Error Handling

When a feature is unavailable, users receive helpful guidance:

```json
{
  "status": "error",
  "error": "HEARTH community database not available",
  "help": "Set HEARTH_PATH environment variable to enable community hunts",
  "suggestion": "Clone HEARTH: git clone https://github.com/THORCollective/HEARTH"
}
```

### Startup Validation

On startup, the server logs feature availability:

```
[INFO] Feature Status:
  HEARTH       : ✓ AVAILABLE
  SPLUNK       : ✗ DISABLED
    → Set SPLUNK_HOST, SPLUNK_PORT, SPLUNK_TOKEN in .env
  NLP          : ✓ AVAILABLE
  ATLASSIAN    : ✗ DISABLED
    → Set ATLASSIAN_URL, ATLASSIAN_USERNAME, ATLASSIAN_API_TOKEN in .env
  PEAK         : ✓ AVAILABLE
  THREAT_INTEL : ✓ AVAILABLE

Features available: 4/6
```

---

## Deployment Best Practices

### Environment Setup

**Minimal (HEARTH only):**
```bash
# Required
HEARTH_PATH=/path/to/HEARTH

# Optional
HUNTS_DIRECTORY=/path/to/hunts  # For PEAK hunts
```

**Full Production:**
```bash
# HEARTH
HEARTH_PATH=/path/to/HEARTH

# Splunk
SPLUNK_HOST=splunk.company.com
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-token

# Atlassian
ATLASSIAN_URL=https://company.atlassian.net
ATLASSIAN_USERNAME=user@company.com
ATLASSIAN_API_TOKEN=your-api-token

# Security
JWT_SECRET=your-secret-key
ENCRYPTION_KEY=your-encryption-key

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

### Health Checks

**Startup Check:**
```bash
# Verify logs show expected features
tail -f /var/log/mcp-server.log | grep "feature_status"
```

**Runtime Monitoring:**
```python
# Call health check periodically
result = await get_server_health()
assert result["status"] in ["healthy", "degraded"]
assert result["features"]["summary"]["available"] >= 3
```

### Performance Tuning

**Redis Caching:**
- Essential for production (40-50% token savings)
- Configure TTL based on data freshness requirements
- Monitor cache hit rates

**Rate Limiting:**
```python
# Configure in security_manager.py
rate_limits = {
    "default": 100,  # requests per minute
    "search": 50,
    "ml_analysis": 10
}
```

**Token Optimization:**
- Use summary mode for list operations
- Request full details only when needed
- Set appropriate pagination limits

### Monitoring Metrics

**Key Metrics:**
- Feature availability (target: 80%+)
- Health check status (target: "healthy")
- Test pass rate (target: 100%)
- Cache hit rate (target: 70%+)
- Average token usage per request
- Error rate by tool

**Alerting:**
- Health status != "healthy"
- Feature availability < 50%
- Test failures
- Redis connection loss

---

## Troubleshooting

### Common Issues

**1. Features Not Available**
```bash
# Check environment variables
grep HEARTH_PATH .env
grep SPLUNK_ .env

# Verify paths exist
ls -la $HEARTH_PATH
```

**2. Tests Failing**
```bash
# Install test dependencies
pip install pytest

# Run with verbose output
pytest tests/ -v --tb=long
```

**3. High Token Usage**
```bash
# Verify summary mode enabled
grep "summary=True" src/tools/hearth_tools.py

# Check Redis caching
redis-cli ping
redis-cli keys "static_content:*"
```

**4. Validation Errors**
```python
# Check input formats
technique_id = "T1003.001"  # Correct
technique_id = "T001"       # Wrong

adversary_id = "G0016"      # Correct
adversary_id = "APT29"      # Wrong
```

---

## Security Considerations

### Input Validation
- All user inputs validated with Pydantic
- SQL/command injection prevention
- Regex pattern validation
- Length and format constraints

### Authentication
- JWT token-based authentication
- Secure credential storage
- Token expiration and renewal

### Audit Logging
- All operations logged in JSON format
- Security events tracked
- SIEM integration ready

### Data Protection
- AES encryption for sensitive data
- Secrets never logged
- Environment variable isolation

---

## Version History

**v1.0.0** (Current)
- ✅ Health monitoring tool
- ✅ Input validation with Pydantic
- ✅ Token optimization (40-50% reduction)
- ✅ Testing infrastructure (38 tests)
- ✅ Structured JSON logging
- ✅ Graceful degradation

---

## Additional Resources

- [Main README](README.md) - Features and usage
- [HEARTH Repository](https://github.com/THORCollective/HEARTH) - Community hunts
- [PEAK Framework Guide](https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template)
- [Test Suite](tests/) - Automated tests
- [Configuration Example](.env.example) - Environment setup
