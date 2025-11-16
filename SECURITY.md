# Security

## Security Features

The Threat Hunting MCP Server implements multiple layers of security to protect sensitive threat hunting operations and data.

### Authentication & Authorization

**JWT Token-Based Authentication:**
- Secure token generation and validation
- Configurable token expiration
- Token binding to specific sessions
- Role-based access control (RBAC)

**Configuration:**
```bash
# Set in .env
JWT_SECRET=your-strong-secret-key-here
```

**Best Practices:**
- Use strong, randomly generated secrets (minimum 32 characters)
- Rotate JWT secrets periodically
- Never commit secrets to version control
- Use environment-specific secrets

### Data Protection

**AES Encryption:**
- Sensitive data encrypted at rest
- Configurable encryption keys
- Secure credential storage
- Protected configuration values

**Configuration:**
```bash
# Set in .env
ENCRYPTION_KEY=your-encryption-key-here
```

**Input Validation:**
- Comprehensive Pydantic validation models
- SQL/command injection prevention
- Format validation (IPs, domains, hashes, MITRE IDs)
- Length and type constraints
- Allowlist-based validation where possible

**Example - Injection Prevention:**
```python
# Blocked query patterns:
- | delete
- | drop
- | outputlookup mode=append
- eval system(...)
```

### Audit Logging

**Structured Audit Logs:**
- All security events logged in JSON format
- User actions tracked
- Failed authentication attempts recorded
- Configuration changes monitored
- SIEM integration ready

**Log Location:**
```bash
# Configure in .env
AUDIT_LOG_PATH=/var/log/threat-hunting-mcp/audit.log
```

**Log Format:**
```json
{
  "timestamp": "2024-11-16T12:00:00Z",
  "event": "authentication_failure",
  "user": "user@example.com",
  "ip_address": "192.168.1.100",
  "details": {"reason": "invalid_token"}
}
```

### Rate Limiting

**Redis-Based Rate Limiting:**
- Sliding window algorithm
- Per-user and per-endpoint limits
- Configurable thresholds
- DDoS protection

**Configuration:**
```python
# Default limits
rate_limits = {
    "default": 100,      # requests per minute
    "search": 50,        # search operations
    "ml_analysis": 10    # ML analysis operations
}
```

**Redis Setup:**
```bash
# Configure in .env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=your-redis-password  # If required
```

### Input Sanitization

**Validation Models:**

All MCP tools use Pydantic validation:

```python
# MITRE Technique IDs
Pattern: T\d{4}(\.\d{3})?
Examples: T1003, T1003.001

# MITRE Group IDs
Pattern: G\d{4}
Examples: G0016 (APT29)

# IP Addresses
Pattern: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
Validation: Each octet 0-255

# Domain Names
Pattern: Valid RFC 1035 domain format
Example: example.com

# Hashes
MD5: 32 hex characters
SHA1: 40 hex characters
SHA256: 64 hex characters
```

### Secrets Management

**Environment Variables:**
Never hardcode secrets. Use environment variables:

```bash
# .env file (add to .gitignore)
JWT_SECRET=...
ENCRYPTION_KEY=...
SPLUNK_TOKEN=...
ATLASSIAN_API_TOKEN=...
REDIS_PASSWORD=...
```

**Best Practices:**
- Use `.env.example` as template (no real secrets)
- Never commit `.env` to version control
- Use different secrets for each environment
- Rotate secrets regularly
- Use secret management tools in production (HashiCorp Vault, AWS Secrets Manager)

### Network Security

**HTTPS/TLS:**
- Use TLS for all network communications
- Validate SSL certificates
- Use strong cipher suites
- Disable weak protocols (SSLv3, TLS 1.0)

**Firewall Configuration:**
```bash
# Allow only required ports
- MCP server port (configure as needed)
- Redis: 6379 (localhost only recommended)
- Splunk API: 8089 (if used)
```

### Dependency Security

**Regular Updates:**
```bash
# Check for vulnerabilities
pip install safety
safety check

# Update dependencies
pip install --upgrade -r requirements.txt
```

**Dependency Scanning:**
- Use Dependabot or similar
- Review security advisories
- Update promptly
- Test after updates

### Secure Configuration

**Minimum Security Configuration:**

```bash
# .env - Security Settings
JWT_SECRET=<strong-32+-char-secret>
ENCRYPTION_KEY=<encryption-key>
AUDIT_LOG_PATH=/var/log/threat-hunting-mcp/audit.log

# Redis (if caching enabled)
REDIS_HOST=localhost  # Don't expose to network
REDIS_PASSWORD=<strong-password>
REDIS_DB=0

# TLS/SSL (recommended for production)
SPLUNK_VERIFY_SSL=true
ATLASSIAN_VERIFY_SSL=true
```

**Production Hardening:**

1. **Use strong secrets:**
   ```bash
   # Generate strong secrets
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Enable HTTPS:**
   - Use reverse proxy (nginx, Apache)
   - Configure TLS certificates
   - Force HTTPS redirects

3. **Restrict access:**
   - Firewall rules
   - IP allowlisting
   - VPN/bastion access only

4. **Monitor logs:**
   - Ship to SIEM
   - Alert on security events
   - Regular log review

5. **Regular updates:**
   - Security patches
   - Dependency updates
   - Configuration reviews

## Security Monitoring

### Key Metrics to Monitor

1. **Authentication Events:**
   - Failed login attempts
   - Unusual access patterns
   - Token validation failures

2. **Rate Limiting:**
   - Rate limit hits
   - Spike in requests
   - Unusual traffic patterns

3. **Input Validation:**
   - Validation failures
   - Injection attempts
   - Malformed requests

4. **System Health:**
   - Unexpected errors
   - Performance degradation
   - Service availability

### SIEM Integration

**Splunk Example:**
```spl
index=threat_hunting_mcp sourcetype=json
| spath event
| search event IN ("authentication_failure", "rate_limit_exceeded", "validation_error")
| stats count by event, user, ip_address
| sort -count
```

**Elasticsearch Example:**
```json
GET /threat-hunting-logs/_search
{
  "query": {
    "terms": {
      "event": ["authentication_failure", "rate_limit_exceeded"]
    }
  },
  "aggs": {
    "by_user": {
      "terms": {"field": "user"}
    }
  }
}
```

## Responsible Disclosure

If you discover a security vulnerability, please follow responsible disclosure:

### DO:
1. **Email security contact** (add contact info)
2. **Provide detailed information:**
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)
3. **Allow time for fix** (90 days)
4. **Coordinate disclosure**

### DON'T:
- Publicly disclose before fix
- Exploit vulnerability
- Access data you don't own
- Perform DoS attacks

### Recognition

We maintain a security hall of fame for responsible disclosures. Contributors will be credited (with permission) in:
- SECURITY.md
- Release notes
- Security advisories

## Security Checklist

### Deployment Checklist

- [ ] Strong JWT_SECRET configured (32+ characters)
- [ ] ENCRYPTION_KEY configured
- [ ] HTTPS/TLS enabled
- [ ] Firewall rules configured
- [ ] Redis password set (if used)
- [ ] Audit logging enabled
- [ ] Rate limiting configured
- [ ] SIEM integration configured
- [ ] Regular backup schedule
- [ ] Security monitoring alerts
- [ ] Dependency scanning enabled
- [ ] SSL certificate validation enabled
- [ ] Default credentials changed
- [ ] Unnecessary services disabled
- [ ] File permissions restricted

### Regular Security Tasks

**Daily:**
- Monitor security logs
- Check for failed authentication
- Review rate limit events

**Weekly:**
- Review audit logs
- Check for unusual patterns
- Verify backup integrity

**Monthly:**
- Update dependencies
- Review firewall rules
- Test incident response
- Security configuration review

**Quarterly:**
- Rotate secrets/keys
- Security audit
- Penetration testing
- Update documentation

## Compliance

This tool can help meet compliance requirements:

- **NIST Cybersecurity Framework**: Detect, Respond functions
- **MITRE ATT&CK**: Threat-informed defense
- **ISO 27001**: Security monitoring and incident detection
- **PCI DSS**: Security monitoring requirements
- **SOC 2**: Security monitoring and logging

Consult with compliance experts for your specific requirements.

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Security is a shared responsibility. Report issues responsibly. Hunt safely! 🛡️**
