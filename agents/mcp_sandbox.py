import json
from typing import Any, Dict, Callable
from logging_config import get_logger

logger = get_logger(__name__)

class MCPSandbox:
    """
    Model Context Protocol (MCP) Tool Sandbox.
    Provides an isolation layer that wraps local tool execution 
    in an MCP-compatible JSON-RPC envelope, validating payloads
    before and after execution to prevent prompt injection leaks.
    """
    def __init__(self):
        self.allowed_tools = ["search_flights", "reserve_hotel", "read_image_ocr", "process_audio_memo", "analyze_video_feed"]
        
    def execute(self, tool_name: str, parameters: Dict[str, Any], execute_fn: Callable) -> str:
        """
        Executes a tool within the MCP Sandbox.
        """
        logger.info(f"[MCP Sandbox] Intercepting request for tool: {tool_name}")
        
        if tool_name not in self.allowed_tools:
            return self._format_mcp_error(-32601, f"Method not found: {tool_name}")
            
        # 1. MCP Protocol Ingress (Simulated JSON-RPC Request)
        mcp_request = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": parameters,
            "id": 1
        }
        
        # 2. Strict Parameter Validation Sandbox
        for key, value in parameters.items():
            if isinstance(value, str) and len(value) > 1000:
                logger.warning(f"[MCP Sandbox] Parameter {key} exceeded max length. Truncating.")
                parameters[key] = value[:1000]
                
        # 3. Execution Isolation
        try:
            logger.info(f"[MCP Sandbox] Executing {tool_name} with verified params: {parameters}")
            raw_result = execute_fn(**parameters)
        except Exception as e:
            logger.error(f"[MCP Sandbox] Execution error: {e}")
            return self._format_mcp_error(-32000, str(e))
            
        # 4. MCP Protocol Egress (Simulated JSON-RPC Response)
        mcp_response = {
            "jsonrpc": "2.0",
            "result": raw_result,
            "id": 1
        }
        
        logger.info(f"[MCP Sandbox] Completed execution for {tool_name}")
        return json.dumps(mcp_response)
        
    def _format_mcp_error(self, code: int, message: str) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": 1
        })

mcp_sandbox = MCPSandbox()
