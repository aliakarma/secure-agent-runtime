"""Manual validation of MCP subprocess isolation (run as a script)."""
import json
import multiprocessing
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if __name__ == "__main__":
    multiprocessing.freeze_support()
    os.environ["MCP_ISOLATION"] = "1"
    os.environ["MCP_SELFCHECK_SECRET"] = "leak-me"  # a "secret" the tool must NOT see
    from agents.mcp_sandbox import mcp_sandbox

    parent_pid = os.getpid()

    # 1) Functional + isolation + secret-scrub via the self-check tool.
    ok, payload = mcp_sandbox._run_isolated("sandbox_selfcheck", {})
    info = json.loads(payload) if ok else {}
    print(f"parent_pid={parent_pid} child_pid={info.get('pid')} "
          f"different_process={info.get('pid') != parent_pid} "
          f"secret_leaked={info.get('secret_visible')}")

    # 2) Real action tool through the full envelope.
    res = mcp_sandbox.execute("search_flights", {"destination": "Paris"}, lambda **k: "INPROC")
    print("search_flights ->", res)

    # 3) Timeout / DoS protection: make the self-check sleep past the timeout.
    os.environ["MCP_TOOL_TIMEOUT"] = "2"
    os.environ["MCP_SELFCHECK_SLEEP"] = "30"
    t0 = time.time()
    ok2, payload2 = mcp_sandbox._run_isolated("sandbox_selfcheck", {})
    print(f"slow_tool killed={not ok2} elapsed={time.time()-t0:.1f}s msg={payload2!r}")
