#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, cast

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


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


class VulnServer:
    def __init__(self) -> None:
        self.server = Server("vuln-server")
        self.setup_tools()

    def setup_tools(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="scan_image",
                    description="Scan container image for vulnerabilities using Trivy",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "image": {"type": "string"},
                            "min_severity": {"type": "string", "default": "HIGH"},
                            "format": {"type": "string", "default": "json"},
                        },
                        "required": ["image"],
                    },
                ),
                Tool(
                    name="scan_filesystem",
                    description="Scan filesystem path for vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "min_severity": {"type": "string", "default": "HIGH"},
                        },
                        "required": ["path"],
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
            if name == "scan_image":
                return await self.scan_image(
                    arguments["image"],
                    arguments.get("min_severity", "HIGH"),
                    arguments.get("format", "json"),
                )
            if name == "scan_filesystem":
                return await self.scan_filesystem(
                    arguments["path"], arguments.get("min_severity", "HIGH")
                )
            if name == "health":
                return [TextContent(type="text", text=json.dumps(self._health(), indent=2))]
            raise ValueError(f"Unknown tool: {name}")

    def _summarize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total = 0
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN")
                if sev in by_sev:
                    by_sev[sev] += 1
                    total += 1
        return {"total_vulnerabilities": total, "by_severity": by_sev}

    async def scan_image(
        self, image: str, min_severity: str = "HIGH", output_format: str = "json"
    ) -> List[TextContent]:
        logger = logging.getLogger(__name__)
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "60"))
        try:
            logger.info(
                "Scanning image image=%s min_severity=%s format=%s",
                image,
                min_severity,
                output_format,
            )
            cmd = [
                "trivy",
                "image",
                "--format",
                output_format,
                "--severity",
                f"{min_severity},CRITICAL",
                "--no-progress",
                image,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=timeout_s
                )
            except TypeError:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if output_format == "json":
                data = json.loads(result.stdout)
                data["summary"] = self._summarize(data)
                logger.debug("Scan summary=%s", data["summary"])
                return [TextContent(type="text", text=json.dumps(data, indent=2))]
            return [TextContent(type="text", text=result.stdout)]
        except subprocess.TimeoutExpired:
            logger.error("Image scan timed out after %ss", timeout_s)
            return [
                TextContent(type="text", text=f"Error: image scan timed out after {timeout_s}s")
            ]
        except subprocess.CalledProcessError as e:
            logger.error("Image scan failed err=%s", e.stderr)
            return [TextContent(type="text", text=f"Error scanning image: {e.stderr}")]

    async def scan_filesystem(self, path: str, min_severity: str = "HIGH") -> List[TextContent]:
        logger = logging.getLogger(__name__)
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "60"))
        try:
            logger.info("Scanning filesystem path=%s min_severity=%s", path, min_severity)
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--severity",
                f"{min_severity},CRITICAL",
                "--no-progress",
                path,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=timeout_s
                )
            except TypeError:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            data["summary"] = self._summarize(data)
            logger.debug("FS scan summary=%s", data["summary"])
            return [TextContent(type="text", text=json.dumps(data, indent=2))]
        except subprocess.TimeoutExpired:
            logger.error("Filesystem scan timed out after %ss", timeout_s)
            return [
                TextContent(
                    type="text", text=f"Error: filesystem scan timed out after {timeout_s}s"
                )
            ]
        except subprocess.CalledProcessError as e:
            logger.error("Filesystem scan failed err=%s", e.stderr)
            return [TextContent(type="text", text=f"Error scanning filesystem: {e.stderr}")]

    def _health(self) -> Dict[str, Any]:
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "10"))
        try:
            try:
                res = subprocess.run(
                    ["trivy", "version"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=timeout_s,
                )
            except TypeError:
                res = subprocess.run(
                    ["trivy", "version"], capture_output=True, text=True, check=True
                )
            return {"status": "ok", "server": "vuln-server", "trivy_version": res.stdout.strip()}
        except Exception as e:
            return {"status": "error", "server": "vuln-server", "error": str(e)}


async def main() -> None:  # pragma: no cover
    _setup_logging()
    server_instance = VulnServer()

    class _NotificationOptions:  # shim for mcp >=1.17.0  # pragma: no cover
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
                server_name="vuln-server",
                server_version="1.0.0",
                capabilities=capabilities,
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    if "--health" in sys.argv:
        data = VulnServer()._health()
        print(json.dumps(data))
        sys.exit(0 if data.get("status") == "ok" else 1)
    asyncio.run(main())  # pragma: no cover
