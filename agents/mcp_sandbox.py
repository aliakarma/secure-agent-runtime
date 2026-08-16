"""
MCP Tool Execution Sandbox.

Provides an MCP-style JSON-RPC envelope around tool execution AND — for the
registered action tools — *real process isolation*: the tool runs in a separate
OS process with a wall-clock timeout and a secret-scrubbed environment, so a
compromised/poisoned tool cannot

  * read the parent's in-memory state or API keys (process boundary + env scrub),
  * hang the agent indefinitely (timeout → the child is killed),
  * or otherwise affect the supervisor beyond its returned string.

An earlier version called ``execute_fn(**parameters)`` directly in-process; the
"Execution Isolation" comment was aspirational. This version makes it real for
the action tools in ``agents.tool_impls.TOOL_REGISTRY``. Heavy read/extraction
tools (OCR/transcription) still run in-process — forking the transformer stack
per call is prohibitive — and that is stated rather than implied.

Controls (env):
  * ``MCP_ISOLATION``     "1" (default) → isolate registry tools in a subprocess.
  * ``MCP_TOOL_TIMEOUT``  seconds before a runaway tool is killed (default 10).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict

from logging_config import get_logger

logger = get_logger(__name__)

# Env keys a sandboxed tool must NOT see (credential exfiltration prevention).
_SECRET_HINTS = ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "_KEY", "CREDENTIAL")


def _scrub_secret_env() -> None:
    for key in list(os.environ.keys()):
        upper = key.upper()
        if any(hint in upper for hint in _SECRET_HINTS):
            os.environ.pop(key, None)


def _sandbox_child(tool_name: str, parameters: Dict[str, Any], out_q) -> None:
    """Runs in the isolated child process: scrub secrets, dispatch by name."""
    try:
        # Defensive: never let a sandbox child itself spawn another sandbox
        # (on Windows `spawn` re-imports __main__; an unguarded entry script
        # could otherwise recurse into a process fork-bomb). Force any nested
        # tool execution in the child to run in-process.
        os.environ["MCP_ISOLATION"] = "0"
        _scrub_secret_env()
        from agents.tool_impls import TOOL_REGISTRY

        impl = TOOL_REGISTRY.get(tool_name)
        if impl is None:
            out_q.put(("err", f"tool '{tool_name}' not in sandbox registry"))
            return
        out_q.put(("ok", impl(**parameters)))
    except Exception as exc:  # pragma: no cover - defensive
        out_q.put(("err", f"{type(exc).__name__}: {exc}"))


# Declared parameter schemas (paper §5.3). Each entry maps a tool to its
# required parameters, its optional parameters, and the expected type of each.
# ``max_len`` bounds any string value; oversize values are truncated rather than
# rejected, because a long-but-well-formed destination is a usability problem
# rather than a protocol violation.
TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "search_flights": {
        "required": {"destination": str},
        "optional": {"origin": str, "date": str},
    },
    "reserve_hotel": {
        "required": {"location": str},
        "optional": {"checkin": str, "checkout": str},
    },
    "read_image_ocr": {"required": {"image_path": str}, "optional": {}},
    "process_audio_memo": {"required": {"audio_path": str}, "optional": {}},
    "analyze_video_feed": {"required": {"video_path": str}, "optional": {}},
    "read_pdf_document": {"required": {"pdf_path": str}, "optional": {}},
    "sandbox_selfcheck": {"required": {}, "optional": {"secret_env": str}},
}

MAX_PARAM_LEN = 1000


class MCPSandbox:
    def __init__(self):
        self.allowed_tools = [
            "search_flights", "reserve_hotel", "read_image_ocr",
            "process_audio_memo", "analyze_video_feed", "read_pdf_document",
        ]

    def _validate_schema(self, tool_name: str, parameters: Dict[str, Any]):
        """Check a call against the tool's declared schema.

        Returns ``(ok, detail)``. Mutates *parameters* in place to truncate
        oversize string values, which is a bound rather than a rejection.
        """
        schema = TOOL_SCHEMAS.get(tool_name)
        if schema is None:
            # An allow-listed tool with no declared schema is a configuration
            # gap, not an attack: bound the values and let it through.
            for key, value in list(parameters.items()):
                if isinstance(value, str) and len(value) > MAX_PARAM_LEN:
                    parameters[key] = value[:MAX_PARAM_LEN]
            return True, "no schema declared"

        required, optional = schema["required"], schema["optional"]
        known = {**required, **optional}

        unknown = set(parameters) - set(known)
        if unknown:
            return False, f"unknown parameter(s): {sorted(unknown)}"

        missing = set(required) - set(parameters)
        if missing:
            return False, f"missing required parameter(s): {sorted(missing)}"

        for key, value in list(parameters.items()):
            expected = known[key]
            if not isinstance(value, expected):
                return False, (
                    f"parameter '{key}' expected {expected.__name__}, "
                    f"got {type(value).__name__}"
                )
            if isinstance(value, str):
                if not value.strip() and key in required:
                    return False, f"required parameter '{key}' is empty"
                if len(value) > MAX_PARAM_LEN:
                    logger.warning(f"[MCP Sandbox] Parameter {key} exceeded max length. Truncating.")
                    parameters[key] = value[:MAX_PARAM_LEN]

        return True, "ok"

    def _isolation_enabled(self) -> bool:
        return os.getenv("MCP_ISOLATION", "1").strip().lower() in ("1", "true", "yes", "on")

    def _timeout(self) -> float:
        try:
            return float(os.getenv("MCP_TOOL_TIMEOUT", "10"))
        except (TypeError, ValueError):
            return 10.0

    def execute(self, tool_name: str, parameters: Dict[str, Any], execute_fn: Callable) -> str:
        logger.info(f"[MCP Sandbox] Intercepting request for tool: {tool_name}")

        if tool_name not in self.allowed_tools:
            return self._format_mcp_error(-32601, f"Method not found: {tool_name}")

        # Phase 3 schema + parameter well-formedness (paper §5.3). This phase
        # is architecturally distinct from the classifier-based hooks: it
        # enforces that the JSON-RPC payload matches the tool's declared
        # parameter schema, not that its content is free of injected
        # instructions. A call carrying unknown parameters, missing required
        # ones, or values of the wrong type never reaches the tool.
        ok, detail = self._validate_schema(tool_name, parameters)
        if not ok:
            logger.warning(f"[MCP Sandbox] Schema violation for {tool_name}: {detail}")
            return self._format_mcp_error(-32602, f"Invalid params: {detail}")

        try:
            from agents.tool_impls import TOOL_REGISTRY
            registered = tool_name in TOOL_REGISTRY
        except Exception:
            registered = False

        if self._isolation_enabled() and registered:
            ok, payload = self._run_isolated(tool_name, parameters)
            if ok:
                raw_result = payload
            else:
                return self._format_mcp_error(-32001, payload)
        else:
            # Heavy read/extraction tools (or isolation disabled): in-process.
            try:
                raw_result = execute_fn(**parameters)
            except Exception as e:
                logger.error(f"[MCP Sandbox] Execution error: {e}")
                return self._format_mcp_error(-32000, str(e))

        logger.info(f"[MCP Sandbox] Completed execution for {tool_name}")
        return json.dumps({"jsonrpc": "2.0", "result": raw_result, "id": 1})

    def _run_isolated(self, tool_name: str, parameters: Dict[str, Any]):
        """Execute a registry tool in a separate process with a timeout.

        Returns ``(True, result_str)`` or ``(False, error_message)``. Falls back
        to in-process execution only if the OS cannot spawn a process at all.
        """
        import multiprocessing as mp

        try:
            ctx = mp.get_context("spawn")
            out_q = ctx.Queue()
            proc = ctx.Process(target=_sandbox_child, args=(tool_name, parameters, out_q), daemon=True)
            proc.start()
            proc.join(self._timeout())
            if proc.is_alive():
                proc.terminate()
                proc.join(2)
                logger.warning(f"[MCP Sandbox] Tool {tool_name} exceeded {self._timeout()}s; killed.")
                return False, f"tool '{tool_name}' timed out after {self._timeout()}s (killed)"
            try:
                status, payload = out_q.get_nowait()
            except Exception:
                return False, f"tool '{tool_name}' produced no result (crashed in sandbox)"
            return (status == "ok"), payload
        except Exception as e:
            # Spawning unavailable (e.g. frozen env) — degrade transparently.
            logger.warning(f"[MCP Sandbox] Isolation unavailable ({e}); running in-process.")
            from agents.tool_impls import TOOL_REGISTRY
            try:
                return True, TOOL_REGISTRY[tool_name](**parameters)
            except Exception as exc:
                return False, str(exc)

    def _format_mcp_error(self, code: int, message: str) -> str:
        return json.dumps({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": 1})


mcp_sandbox = MCPSandbox()
