#!/usr/bin/env python
"""
MCP Stdio Bridge for AI Chat Room.

Use this entry point for MCP clients configured to use stdio (like Claude Desktop).
It connects to the shared SQLite database and logs in f:/AI/ai-chat/data/chat.db.
"""
import sys
from pathlib import Path

# Ensure package is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aichat.mcp_server import mcp

if __name__ == "__main__":
    mcp.run(transport="stdio")
