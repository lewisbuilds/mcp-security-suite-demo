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


class SBOMServer:
    def __init__(self) -> None:
        self.server = Server("sbom-server")
        self.setup_tools()

    def setup_tools(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="generate_sbom",
                    description="Generate SBOM for container image using Syft",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "image": {"type": "string"},
                            "format": {"type": "string", "default": "json"},
                        },
                        "required": ["image"],
                    },
                ),
                Tool(
                    name="diff_packages",
                    description="Compare package differences between two Syft JSON SBOMs",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "old_sbom": {"type": "string", "description": "SBOM JSON (string)"},
                            "new_sbom": {"type": "string", "description": "SBOM JSON (string)"},
                        },
                        "required": ["old_sbom", "new_sbom"],
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
            if name == "generate_sbom":
                return await self.generate_sbom(arguments["image"], arguments.get("format", "json"))
            if name == "diff_packages":
                return await self.diff_packages(arguments["old_sbom"], arguments["new_sbom"])
            if name == "health":
                return [TextContent(type="text", text=json.dumps(self._health(), indent=2))]
            raise ValueError(f"Unknown tool: {name}")

    async def generate_sbom(self, image: str, output_format: str = "json") -> List[TextContent]:
        logger = logging.getLogger(__name__)
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "60"))
        try:
            logger.info("Generating SBOM image=%s format=%s", image, output_format)
            cmd = ["syft", image, "-o", output_format]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=timeout_s
                )
            except TypeError:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if output_format == "json":
                data = json.loads(result.stdout)
                logger.debug("SBOM artifacts=%s", len(data.get("artifacts", [])))
                return [TextContent(type="text", text=json.dumps(data, indent=2))]
            return [TextContent(type="text", text=result.stdout)]
        except subprocess.TimeoutExpired:
            logger.error("SBOM generation timed out after %ss", timeout_s)
            return [
                TextContent(
                    type="text", text=f"Error: SBOM generation timed out after {timeout_s}s"
                )
            ]
        except subprocess.CalledProcessError as e:
            logger.error("SBOM generation failed err=%s", e.stderr)
            return [TextContent(type="text", text=f"Error generating SBOM: {e.stderr}")]

    async def diff_packages(self, old_sbom: str, new_sbom: str) -> List[TextContent]:
        old = json.loads(old_sbom)
        new = json.loads(new_sbom)

        def extract(data: Dict[str, Any]) -> set[str]:
            names: set[str] = set()
            for artifact in data.get("artifacts", []):
                name = artifact.get("name")
                ver = artifact.get("version", "")
                if name:
                    names.add(f"{name}:{ver}")
            return names

        old_pkgs = extract(old)
        new_pkgs = extract(new)
        diff = {
            "added": sorted(new_pkgs - old_pkgs),
            "removed": sorted(old_pkgs - new_pkgs),
            "summary": {
                "added_count": len(new_pkgs - old_pkgs),
                "removed_count": len(old_pkgs - new_pkgs),
            },
        }
        return [TextContent(type="text", text=json.dumps(diff, indent=2))]

    def _health(self) -> Dict[str, Any]:
        timeout_s = int(os.getenv("TOOL_TIMEOUT", "10"))
        try:
            try:
                res = subprocess.run(
                    ["syft", "version"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=timeout_s,
                )
            except TypeError:
                res = subprocess.run(
                    ["syft", "version"], capture_output=True, text=True, check=True
                )
            return {"status": "ok", "server": "sbom-server", "syft_version": res.stdout.strip()}
        except Exception as e:
            return {"status": "error", "server": "sbom-server", "error": str(e)}


async def main() -> None:  # pragma: no cover
    _setup_logging()
    server_instance = SBOMServer()

    # mcp 1.17.0 requires a notification_options object with attribute tools_changed.
    class _NotificationOptions:  # simple shim to satisfy library expectation  # pragma: no cover
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
                server_name="sbom-server",
                server_version="1.0.0",
                capabilities=capabilities,
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    if "--health" in sys.argv:
        data = SBOMServer()._health()
        print(json.dumps(data))
        sys.exit(0 if data.get("status") == "ok" else 1)
    asyncio.run(main())  # pragma: no cover
