"""Tests for the MCP execution sandbox: gating, registry dispatch, and real
process isolation (separate PID, secret scrub, timeout/DoS kill)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.mcp_sandbox import mcp_sandbox


def test_method_not_found_for_unlisted_tool():
    out = json.loads(mcp_sandbox.execute("rm_rf", {}, lambda **k: "x"))
    assert out["error"]["code"] == -32601


def test_in_process_path_uses_execute_fn_when_isolation_off():
    os.environ["MCP_ISOLATION"] = "0"
    try:
        out = json.loads(mcp_sandbox.execute("search_flights", {"destination": "Rome"}, lambda **k: "MOCK"))
        assert out["result"] == "MOCK"  # isolation off → the passed fn runs in-process
    finally:
        os.environ.pop("MCP_ISOLATION", None)


def test_real_process_isolation_secret_scrub_and_timeout():
    """Run the spawn-based isolation check in a child interpreter (avoids
    pytest + multiprocessing-spawn re-import issues) and assert on its report."""
    env = dict(os.environ, LANGCHAIN_TRACING_V2="false")
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "_sandbox_check.py")],
        capture_output=True, text=True, timeout=120, env=env,
    )
    out = proc.stdout
    # 1) executed in a different process, 2) secret env var did NOT leak in.
    assert "different_process=True" in out, out
    assert "secret_leaked=False" in out, out
    # 3) a tool that runs past the timeout is killed.
    assert "slow_tool killed=True" in out, out
