#!/usr/bin/env python
"""
MCP Stdio Bridge for AI Chat Room.

Use this entry point for MCP clients configured to use stdio (like Claude Desktop).
It connects to the shared SQLite database and logs in f:/AI/ai-chat/data/chat.db.
"""
import os
import sys
from pathlib import Path

# Ensure package is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Explicitly authorize production DB for stdio bridge launcher
os.environ["AICHAT_ALLOW_DEFAULT_DB"] = "1"

from aichat.mcp_server import init_stdio_mode, mcp

if __name__ == "__main__":
    token = os.environ.get("AICHAT_AGENT_TOKEN") or os.environ.get("AI_CHAT_AGENT_TOKEN")
    init_stdio_mode(token)
    mcp.run(transport="stdio")
