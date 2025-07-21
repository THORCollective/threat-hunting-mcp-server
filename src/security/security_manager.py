from cryptography.fernet import Fernet
import jwt
from datetime import datetime, timedelta
import hashlib
import asyncio
import json
import logging
import structlog
from functools import wraps
from typing import Dict, Optional, List, Any
import redis.asyncio as redis
from pathlib import Path

logger = structlog.get_logger()


class SecurityManager:
    """Implements comprehensive security controls for MCP server"""
    
    def __init__(self, config: Dict):
        self.encryption_key = self._get_or_generate_key(config.get('encryption_key'))
        self.cipher = Fernet(self.encryption_key)
        self.jwt_secret = config['jwt_secret']
        self.audit_logger = AuditLogger(config.get('audit_config', {}))
        self.rate_limiter = RateLimiter(config.get('redis', {}))
        self.current_user = None
        
    def authenticate_request(self, token: str) -> Dict:
        """Validates JWT tokens with security checks"""
        try:
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=['RS256', 'HS256'],
                options={'require': ['exp', 'iat', 'sub', 'aud']}
            )
            
            # Validate token expiration
            if datetime.utcnow().timestamp() > payload['exp']:
                raise ValueError("Token expired")
            
            # Validate issuer and audience
            if not self._validate_token_claims(payload):
                raise ValueError("Invalid token claims")
                
            # Check token binding (if implemented)
            if 'token_binding' in payload:
                if not self._validate_token_binding(payload, token):
                    raise ValueError("Token binding mismatch")
            
            self.current_user = payload
            return payload
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
            
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypts sensitive data at rest"""
        if not isinstance(data, str):
            data = json.dumps(data)
        return self.cipher.encrypt(data.encode()).decode()
        
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypts sensitive data"""
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise ValueError("Failed to decrypt data")
        
    async def audit_log(self, action: str, user: str, details: Dict, 
                       severity: str = "INFO"):
        """Comprehensive audit logging for compliance"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user': user,
            'action': action,
            'details': details,
            'session_id': self._get_session_id(),
            'ip_address': self._get_client_ip(),
            'user_agent': self._get_user_agent(),
            'severity': severity,
            'source': 'threat_hunting_mcp'
        }
        
        # Log to structured logger
        await self.audit_logger.log(log_entry)
        
        # Also log security-relevant events to security log
        if severity in ['WARNING', 'ERROR', 'CRITICAL']:
            await self.audit_logger.security_log(log_entry)
        
    def rate_limit(self, key: str, max_requests: int = 100, 
                  window_seconds: int = 3600):
        """Implements rate limiting with sliding window"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                user_key = f"{self.get_current_user()}:{key}"
                if not await self.rate_limiter.check_rate_limit(
                    user_key, max_requests, window_seconds
                ):
                    await self.audit_log(
                        "rate_limit_exceeded", 
                        self.get_current_user(),
                        {"key": key, "limit": max_requests},
                        "WARNING"
                    )
                    raise ValueError("Rate limit exceeded")
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_auth(self, func):
        """Decorator to require authentication"""
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not self.current_user:
                raise ValueError("Authentication required")
            return await func(*args, **kwargs)
        return wrapper
    
    def require_permission(self, permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                if not self.has_permission(permission):
                    await self.audit_log(
                        "permission_denied",
                        self.get_current_user(),
                        {"permission": permission, "function": func.__name__},
                        "WARNING"
                    )
                    raise ValueError(f"Permission '{permission}' required")
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def has_permission(self, permission: str) -> bool:
        """Checks if current user has specific permission"""
        if not self.current_user:
            return False
        
        user_permissions = self.current_user.get('permissions', [])
        user_roles = self.current_user.get('roles', [])
        
        # Direct permission check
        if permission in user_permissions:
            return True
        
        # Role-based permission check
        role_permissions = self._get_role_permissions()
        for role in user_roles:
            if permission in role_permissions.get(role, []):
                return True
        
        return False
    
    def get_current_user(self) -> str:
        """Gets current authenticated user"""
        if self.current_user:
            return self.current_user.get('sub', 'unknown')
        return 'anonymous'
    
    def sanitize_input(self, input_data: Any) -> Any:
        """Sanitizes input data to prevent injection attacks"""
        if isinstance(input_data, str):
            # Remove potentially dangerous characters for SPL injection
            dangerous_chars = [';', '|eval', '|delete', '|drop', 'rm -rf']
            for char in dangerous_chars:
                if char in input_data.lower():
                    logger.warning("Potentially dangerous input detected", 
                                 input=input_data, char=char)
                    input_data = input_data.replace(char, '')
            
            # Limit input length
            if len(input_data) > 10000:
                input_data = input_data[:10000]
                
        elif isinstance(input_data, dict):
            return {k: self.sanitize_input(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [self.sanitize_input(item) for item in input_data]
        
        return input_data
    
    def validate_splunk_query(self, query: str) -> bool:
        """Validates Splunk queries for security"""
        dangerous_commands = [
            'delete', 'drop', 'outputcsv', 'outputlookup', 
            'script', 'sendemail', 'rest'
        ]
        
        query_lower = query.lower()
        for cmd in dangerous_commands:
            if cmd in query_lower:
                logger.warning("Dangerous Splunk command detected", 
                             query=query, command=cmd)
                return False
        
        # Check for excessive wildcards
        if query.count('*') > 10:
            logger.warning("Excessive wildcards in query", query=query)
            return False
            
        return True
    
    def _get_or_generate_key(self, provided_key: Optional[str]) -> bytes:
        """Gets or generates encryption key"""
        if provided_key:
            return provided_key.encode()[:32].ljust(32, b'0')
        else:
            # Generate new key (in production, store securely)
            return Fernet.generate_key()
    
    def _validate_token_claims(self, payload: Dict) -> bool:
        """Validates JWT token claims"""
        required_claims = ['sub', 'iat', 'exp']
        for claim in required_claims:
            if claim not in payload:
                return False
        
        # Validate audience (if configured)
        expected_audience = "threat_hunting_mcp"
        if 'aud' in payload and payload['aud'] != expected_audience:
            return False
        
        return True
    
    def _validate_token_binding(self, payload: Dict, token: str) -> bool:
        """Validates token binding to prevent token theft"""
        # This would implement token binding validation
        # For now, return True (implement based on your requirements)
        return True
    
    def _get_session_id(self) -> str:
        """Gets current session ID"""
        if self.current_user:
            return self.current_user.get('session_id', 'unknown')
        return 'no_session'
    
    def _get_client_ip(self) -> str:
        """Gets client IP address"""
        # This would be implemented based on your transport mechanism
        return 'unknown'
    
    def _get_user_agent(self) -> str:
        """Gets user agent string"""
        # This would be implemented based on your transport mechanism
        return 'mcp_client'
    
    def _get_role_permissions(self) -> Dict[str, List[str]]:
        """Returns role-based permissions mapping"""
        return {
            'admin': [
                'hunt:create', 'hunt:execute', 'hunt:delete', 
                'query:splunk', 'config:modify', 'user:manage'
            ],
            'analyst': [
                'hunt:create', 'hunt:execute', 'query:splunk'
            ],
            'viewer': [
                'hunt:view', 'query:view'
            ]
        }


class AuditLogger:
    """Handles audit logging with multiple outputs"""
    
    def __init__(self, config: Dict):
        self.log_file = config.get('log_file', '/var/log/threat_hunting_mcp/audit.log')
        self.security_log_file = config.get('security_log_file', 
                                          '/var/log/threat_hunting_mcp/security.log')
        self.siem_enabled = config.get('siem_enabled', False)
        self.siem_endpoint = config.get('siem_endpoint')
        
        # Ensure log directories exist
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.security_log_file).parent.mkdir(parents=True, exist_ok=True)
        
    async def log(self, log_entry: Dict):
        """Logs audit entry to file and optionally SIEM"""
        # Log to file
        await self._log_to_file(log_entry, self.log_file)
        
        # Log to SIEM if enabled
        if self.siem_enabled and self.siem_endpoint:
            await self._log_to_siem(log_entry)
    
    async def security_log(self, log_entry: Dict):
        """Logs security-relevant entries to dedicated security log"""
        await self._log_to_file(log_entry, self.security_log_file)
    
    async def _log_to_file(self, log_entry: Dict, file_path: str):
        """Logs entry to file"""
        try:
            with open(file_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error("Failed to write audit log", error=str(e))
    
    async def _log_to_siem(self, log_entry: Dict):
        """Sends log entry to SIEM"""
        # Implementation would depend on your SIEM
        # This is a placeholder
        logger.info("Would send to SIEM", entry=log_entry)


class RateLimiter:
    """Redis-based rate limiting"""
    
    def __init__(self, redis_config: Dict):
        self.redis_pool = None
        if redis_config:
            self.redis_pool = redis.ConnectionPool(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password')
            )
    
    async def check_rate_limit(self, key: str, max_requests: int, 
                             window_seconds: int) -> bool:
        """Checks if request is within rate limit using sliding window"""
        if not self.redis_pool:
            # If no Redis, allow all requests (not recommended for production)
            return True
        
        try:
            redis_conn = redis.Redis(connection_pool=self.redis_pool)
            
            now = datetime.utcnow().timestamp()
            window_start = now - window_seconds
            
            # Use sliding window log approach
            pipe = redis_conn.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = await pipe.execute()
            current_requests = results[1]
            
            return current_requests < max_requests
            
        except Exception as e:
            logger.error("Rate limiting failed", error=str(e))
            # Fail open - allow request if rate limiting fails
            return True


class CacheManager:
    """Manages caching for threat intelligence data"""
    
    def __init__(self, redis_config: Dict):
        self.redis_pool = None
        if redis_config:
            self.redis_pool = redis.ConnectionPool(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password')
            )
        
        self.ttl_config = {
            'mitre_techniques': 86400,    # 24 hours
            'threat_actors': 14400,       # 4 hours
            'ioc_lookups': 3600,         # 1 hour
            'hunt_results': 7200,        # 2 hours
            'static_playbooks': 604800   # 7 days
        }
        
    async def get_or_compute(self, key: str, compute_func, ttl_type: str):
        """Cache-aside pattern with automatic computation"""
        if not self.redis_pool:
            # No caching, compute directly
            return await compute_func()
        
        try:
            redis_conn = redis.Redis(connection_pool=self.redis_pool)
            
            # Try cache first
            cached = await redis_conn.get(key)
            if cached:
                return json.loads(cached)
            
            # Compute if not cached
            result = await compute_func()
            
            # Store with appropriate TTL
            ttl = self.ttl_config.get(ttl_type, 3600)
            await redis_conn.setex(key, ttl, json.dumps(result))
            
            return result
            
        except Exception as e:
            logger.error("Cache operation failed", error=str(e))
            # Fallback to direct computation
            return await compute_func()
        
    async def invalidate_pattern(self, pattern: str):
        """Invalidates cache entries matching pattern"""
        if not self.redis_pool:
            return
        
        try:
            redis_conn = redis.Redis(connection_pool=self.redis_pool)
            cursor = 0
            while True:
                cursor, keys = await redis_conn.scan(
                    cursor, match=pattern, count=100
                )
                if keys:
                    await redis_conn.delete(*keys)
                if cursor == 0:
                    break
        except Exception as e:
            logger.error("Cache invalidation failed", error=str(e))
    
    async def set(self, key: str, value: Any, ttl_type: str):
        """Sets a cache value"""
        if not self.redis_pool:
            return
        
        try:
            redis_conn = redis.Redis(connection_pool=self.redis_pool)
            ttl = self.ttl_config.get(ttl_type, 3600)
            await redis_conn.setex(key, ttl, json.dumps(value))
        except Exception as e:
            logger.error("Cache set failed", error=str(e))