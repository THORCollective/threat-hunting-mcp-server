# Contributing to Threat Hunting MCP Server

Thank you for your interest in contributing to the Threat Hunting MCP Server! This guide will help you get started with development.

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- Basic understanding of MCP (Model Context Protocol)
- Familiarity with threat hunting concepts

### Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/threat-hunting-mcp-server
   cd threat-hunting-mcp-server
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install pytest  # For testing
   ```

4. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your development settings
   ```

## Project Structure

```
threat_hunting_mcp/
├── src/
│   ├── models/          # Data models and validators
│   │   ├── hunt.py      # Hunt data models
│   │   └── validators.py # Pydantic validation models
│   ├── frameworks/      # Hunting frameworks
│   │   ├── hunt_framework.py # PEAK, SQRRL frameworks
│   │   └── tahiti.py    # TaHiTI framework
│   ├── integrations/    # External integrations
│   │   ├── splunk.py    # Splunk integration
│   │   └── atlassian.py # Jira/Confluence integration
│   ├── intelligence/    # Threat intelligence
│   │   ├── threat_intel.py # MITRE ATT&CK, threat intel
│   │   └── hearth_integration.py # HEARTH community hunts
│   ├── tools/           # MCP tools
│   │   ├── hearth_tools.py # HEARTH community tools
│   │   └── peak_tools.py    # PEAK framework tools
│   ├── nlp/            # Natural language processing
│   │   └── hunt_nlp.py # NLP for threat hunting
│   ├── security/       # Security controls
│   │   └── security_manager.py # Auth, encryption, caching
│   ├── cognitive/      # Cognitive hunting capabilities
│   ├── correlation/    # Graph correlation engine
│   ├── deception/      # Deception technology
│   ├── config.py       # Configuration management
│   └── server.py       # Main MCP server
├── tests/              # Test suite
│   ├── conftest.py     # Pytest configuration
│   ├── test_validators.py
│   ├── test_server_health.py
│   └── test_hearth_integration.py
├── examples/           # Example PEAK hunt reports
├── hunts/             # Your PEAK hunt reports
├── requirements.txt    # Python dependencies
├── pytest.ini         # Pytest configuration
└── .env.example      # Environment template
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Your Changes

Follow the coding standards below and ensure your changes:
- Are focused and atomic
- Include appropriate tests
- Follow existing code patterns
- Don't break existing functionality

### 3. Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test categories
pytest -m unit
pytest -m validation
pytest -m health

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### 4. Commit Your Changes

Use conventional commit format:

```bash
git commit -m "feat: add new threat hunting tool"
git commit -m "fix: resolve validation error in IOC enrichment"
git commit -m "docs: update API documentation"
git commit -m "test: add tests for behavioral hunt creation"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or modifications
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

### 5. Submit a Pull Request

1. Push your branch to your fork
2. Open a pull request against `main`
3. Describe your changes clearly
4. Link related issues
5. Wait for review

## Coding Standards

### Python Style

- Follow PEP 8 style guide
- Use type hints for function parameters and return values
- Maximum line length: 100 characters (soft limit, use judgment)
- Use docstrings for all public functions and classes

**Example:**
```python
from typing import Dict, List, Optional

async def search_hunts(
    tactic: Optional[str] = None,
    tags: Optional[List[str]] = None,
    limit: int = 5
) -> Dict:
    """
    Search threat hunting hypotheses.

    Args:
        tactic: MITRE ATT&CK tactic filter
        tags: Tag filters
        limit: Maximum results (default: 5)

    Returns:
        Dictionary with search results
    """
    # Implementation
    pass
```

### Code Organization

- One class per file (generally)
- Group related functions together
- Keep functions focused and small
- Use meaningful variable names
- Add comments for complex logic

### Error Handling

```python
# Good: Specific error handling with helpful messages
try:
    hunt = self.repo.get_hunt_by_id(hunt_id)
except HuntNotFoundError:
    return {
        "status": "error",
        "error": f"Hunt {hunt_id} not found",
        "help": "Use search_community_hunts() to find available hunts"
    }

# Bad: Generic error handling
try:
    hunt = self.repo.get_hunt_by_id(hunt_id)
except Exception as e:
    return {"error": str(e)}
```

## Adding New Features

### Adding a New MCP Tool

1. **Define the tool in `server.py`**:
   ```python
   @self.mcp.tool()
   async def your_new_tool(param: str) -> Dict:
       """Tool description"""
       try:
           # Implementation
           return {"status": "success", "data": result}
       except Exception as e:
           logger.error(f"Error in your_new_tool: {e}")
           return {"status": "error", "error": str(e)}
   ```

2. **Add validation** in `models/validators.py`:
   ```python
   class YourToolRequest(BaseModel):
       param: str = Field(..., min_length=1, description="Parameter description")

       @field_validator('param')
       @classmethod
       def validate_param(cls, v: str) -> str:
           # Validation logic
           return v
   ```

3. **Write tests** in `tests/test_your_tool.py`:
   ```python
   @pytest.mark.unit
   def test_your_tool_valid_input():
       request = YourToolRequest(param="value")
       assert request.param == "value"
   ```

4. **Update documentation**:
   - Add to README.md (if major feature)
   - Add to API_REFERENCE.md
   - Add docstring with examples

### Adding a New Hunt Type

1. **Define in `models/hunt.py`**:
   ```python
   class HuntType(str, Enum):
       EXISTING = "existing"
       YOUR_NEW_TYPE = "your_new_type"
   ```

2. **Implement in `frameworks/hunt_framework.py`**:
   ```python
   def create_your_hunt_type(self, ...):
       # Creation logic
       pass
   ```

3. **Add execution logic** if needed

4. **Add tests and documentation**

### Extending Intelligence Frameworks

1. Add framework to `intelligence/threat_intel.py`
2. Update analysis methods
3. Add framework resources
4. Document methodology in FRAMEWORKS.md

## Testing Guidelines

### Test Categories

Use pytest markers to categorize tests:

```python
@pytest.mark.unit          # Fast, no external dependencies
@pytest.mark.validation    # Input validation tests
@pytest.mark.integration   # Requires external services
@pytest.mark.health        # Health check tests
@pytest.mark.slow          # Slow-running tests
```

### Writing Good Tests

```python
class TestYourFeature:
    """Group related tests in a class"""

    @pytest.mark.unit
    def test_valid_input(self):
        """Test description in present tense"""
        # Arrange
        input_data = {"key": "value"}

        # Act
        result = your_function(input_data)

        # Assert
        assert result["status"] == "success"
        assert "data" in result
```

### Test Coverage

- Aim for 70%+ coverage on new code
- Test both success and failure cases
- Test edge cases and boundary conditions
- Test validation logic thoroughly

## Security Guidelines

### Never Commit Secrets

- Use environment variables for credentials
- Never hardcode API keys, tokens, passwords
- Add sensitive files to `.gitignore`
- Use `.env.example` as a template

### Input Validation

- Always validate user inputs with Pydantic
- Sanitize inputs to prevent injection
- Use allowlists when possible
- Validate format, length, and type

### Example:
```python
# Good: Validated input
class QueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)

    @field_validator('query')
    @classmethod
    def validate_query(cls, v: str) -> str:
        dangerous_patterns = [r'\|\\s*delete', r'\|\\s*drop']
        for pattern in dangerous_patterns:
            if re.search(pattern, v.lower()):
                raise ValueError("Dangerous query pattern detected")
        return v
```

## Documentation

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> Dict:
    """
    Brief description of function.

    Longer description if needed. Explain the purpose,
    behavior, and any important details.

    Args:
        param1: Description of parameter 1
        param2: Description of parameter 2

    Returns:
        Dictionary containing result with keys:
        - status: Success or error status
        - data: Result data

    Raises:
        ValueError: When input is invalid

    Example:
        >>> result = function_name("test", 42)
        >>> print(result["status"])
        success
    """
    pass
```

### README and Documentation

- Update README.md for major features
- Add examples for new tools
- Document configuration options
- Update PRODUCTION.md for operational changes

## Performance Considerations

### Token Optimization

- Use summary mode for list operations
- Implement caching for static data
- Keep pagination defaults low (5-10 items)
- Avoid loading full datasets unnecessarily

### Caching

```python
# Use Redis caching for expensive operations
cache_key = f"namespace:{identifier}"
cached = await self.cache.get(cache_key)
if cached:
    return cached

result = expensive_operation()
await self.cache.set(cache_key, result, ttl=3600)
return result
```

## Review Process

### What Reviewers Look For

1. **Functionality**: Does it work as intended?
2. **Tests**: Are there adequate tests?
3. **Security**: Any security concerns?
4. **Performance**: Any performance issues?
5. **Style**: Follows coding standards?
6. **Documentation**: Is it documented?

### Responding to Reviews

- Be open to feedback
- Ask questions if unclear
- Make requested changes promptly
- Update tests as needed
- Re-request review when ready

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Create a GitHub Issue
- **Security**: See SECURITY.md for responsible disclosure
- **Chat**: Join our community (link TBD)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to behavioral threat hunting! 🔍🛡️**
