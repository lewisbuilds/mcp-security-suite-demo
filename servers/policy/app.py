#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, cast

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool


def _setup_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            import json as _json
            import time as _time

            ts = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(record.created))
            return _json.dumps(
                {
                    "ts": ts,
                    "level": record.levelname,
                    "name": record.name,
                    "msg": record.getMessage(),
                }
            )

    handler = logging.StreamHandler(sys.stdout)
    if os.getenv("LOG_FORMAT", "").lower() == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))

    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


class PolicyServer:
    def __init__(self) -> None:
        self.server = Server("policy-server")
        self.setup_tools()

    def setup_tools(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="evaluate",
                    description="Evaluate input against OPA policy",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "input_data": {"type": "object"},
                            "policy_file": {"type": "string", "default": "policy.rego"},
                            "query": {"type": "string", "default": "data.security.policy"},
                        },
                        "required": ["input_data"],
                    },
                ),
                Tool(
                    name="validate_policy",
                    description="Validate Rego policy syntax",
                    inputSchema={
                        "type": "object",
                        "properties": {"policy_file": {"type": "string", "default": "policy.rego"}},
                    },
                ),
                Tool(
                    name="health",
                    description="Return server health and tool versions",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            if name == "evaluate":
                return await self.evaluate(
                    arguments["input_data"],
                    arguments.get("policy_file", "policy.rego"),
                    arguments.get("query", "data.security.policy"),
                )
            if name == "validate_policy":
                return await self.validate_policy(arguments.get("policy_file", "policy.rego"))
            if name == "health":
                return [TextContent(type="text", text=json.dumps(self._health(), indent=2))]
            raise ValueError(f"Unknown tool: {name}")

    async def evaluate(
        self,
        input_data: Dict[str, Any],
        policy_file: str = "policy.rego",
        query: str = "data.security.policy",
    ) -> List[TextContent]:
        logger = logging.getLogger(__name__)
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "60"))
        input_path = None
        try:
            logger.info("Evaluating policy file=%s query=%s", policy_file, query)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(input_data, f)
                input_path = f.name
            cmd = [
                "opa",
                "eval",
                "--data",
                policy_file,
                "--input",
                input_path,
                "--format",
                "json",
                query,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=timeout_s
                )
            except TypeError:
                # Some test stubs may not accept the 'timeout' kwarg; retry without it
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            value = (data.get("result") or [{}])[0].get("value", {})
            evaluation = {
                "allow": value.get("allow", False),
                "violations": value.get("violations", []),
                "risk_level": value.get("risk_level", "UNKNOWN"),
            }
            logger.debug(
                "Policy result allow=%s risk=%s", evaluation["allow"], evaluation["risk_level"]
            )
            return [TextContent(type="text", text=json.dumps(evaluation, indent=2))]
        except subprocess.CalledProcessError as e:
            logger.error("Policy evaluation failed err=%s", e.stderr)
            return [TextContent(type="text", text=f"Error evaluating policy: {e.stderr}")]
        except subprocess.TimeoutExpired:
            logger.error("Policy evaluation timed out after %ss", timeout_s)
            return [
                TextContent(
                    type="text", text=f"Error: policy evaluation timed out after {timeout_s}s"
                )
            ]
        finally:
            if input_path:
                try:
                    os.remove(input_path)
                except OSError:
                    logging.getLogger(__name__).warning(
                        "Temporary input file cleanup failed path=%s", input_path
                    )

    async def validate_policy(self, policy_file: str = "policy.rego") -> List[TextContent]:
        logger = logging.getLogger(__name__)
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "60"))
        try:
            try:
                result = subprocess.run(
                    ["opa", "fmt", "--diff", policy_file],
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
            except TypeError:
                result = subprocess.run(
                    ["opa", "fmt", "--diff", policy_file],
                    capture_output=True,
                    text=True,
                )
        except subprocess.TimeoutExpired:
            logger.error("Policy validation timed out after %ss", timeout_s)
            return [
                TextContent(type="text", text=f"Policy validation timed out after {timeout_s}s")
            ]
        if result.returncode == 0:
            return [TextContent(type="text", text=f"Policy {policy_file} is valid")]
        logger.error("Policy validation failed file=%s err=%s", policy_file, result.stderr)
        return [TextContent(type="text", text=f"Policy validation failed: {result.stderr}")]

    def _health(self) -> Dict[str, Any]:
        """Return basic health data including OPA version.

        This is a quick check that the required binary is present and executable.
        """
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "10"))
        try:
            try:
                res = subprocess.run(
                    ["opa", "version"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=timeout_s,
                )
            except TypeError:
                res = subprocess.run(["opa", "version"], capture_output=True, text=True, check=True)
            return {"status": "ok", "server": "policy-server", "opa_version": res.stdout.strip()}
        except Exception as e:  # broad by design for health surface
            return {"status": "error", "server": "policy-server", "error": str(e)}


async def main() -> None:  # pragma: no cover
    _setup_logging()
    server_instance = PolicyServer()

    class _NotificationOptions:  # pragma: no cover
        def __init__(self, tools_changed: bool = False) -> None:
            self.tools_changed = tools_changed

    async with stdio_server() as (read_stream, write_stream):  # pragma: no cover
        server_any = cast(Any, server_instance.server)
        try:
            capabilities = server_any.get_capabilities(
                notification_options=_NotificationOptions(), experimental_capabilities={}
            )
        except TypeError:
            try:
                capabilities = server_any.get_capabilities(_NotificationOptions())
            except TypeError:
                capabilities = server_any.get_capabilities()
        await server_instance.server.run(  # pragma: no cover
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="policy-server",
                server_version="1.0.0",
                capabilities=capabilities,
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    if "--health" in sys.argv:
        data = PolicyServer()._health()
        # Print plain JSON for Docker healthcheck consumption
        print(json.dumps(data))
        sys.exit(0 if data.get("status") == "ok" else 1)
    asyncio.run(main())  # pragma: no cover
