#!/usr/bin/env python3
"""
Entry point for the Threat Hunting MCP Server
"""

import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import and run the MCP server directly
# The FastMCP framework will handle the async event loop
if __name__ == "__main__":
    from src.server import ThreatHuntingMCPServer
    import structlog

    logger = structlog.get_logger()

    try:
        logger.info("Initializing Threat Hunting MCP Server")
        server = ThreatHuntingMCPServer()

        # FastMCP handles running the server - just execute it
        # This will be run by the MCP framework's event loop
        server.mcp.run()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error("Server initialization failed", error=str(e))
        sys.exit(1)