#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
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


class ReportServer:
    def __init__(self) -> None:
        self.server = Server("report-server")
        self.setup_tools()

    def setup_tools(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="aggregate",
                    description="Aggregate SBOM, vuln, and policy results into a compliance report",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "build_id": {"type": "string"},
                            "image": {"type": "string"},
                            "sbom_data": {"type": "object"},
                            "vuln_findings": {"type": "object"},
                            "policy_evaluation": {"type": "object"},
                            "metadata": {"type": "object"},
                        },
                        "required": ["build_id", "image"],
                    },
                ),
                Tool(
                    name="generate_summary",
                    description="Produce an executive summary from a compliance report",
                    inputSchema={
                        "type": "object",
                        "properties": {"report_data": {"type": "object"}},
                        "required": ["report_data"],
                    },
                ),
                Tool(
                    name="health",
                    description="Return server health",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            if name == "aggregate":
                return await self.aggregate(
                    arguments["build_id"],
                    arguments["image"],
                    arguments.get("sbom_data", {}),
                    arguments.get("vuln_findings", {}),
                    arguments.get("policy_evaluation", {}),
                    arguments.get("metadata", {}),
                )
            if name == "generate_summary":
                return await self.generate_summary(arguments["report_data"])
            if name == "health":
                return [TextContent(type="text", text=json.dumps(self._health(), indent=2))]
            raise ValueError(f"Unknown tool: {name}")

    async def aggregate(
        self,
        build_id: str,
        image: str,
        sbom_data: Dict[str, Any],
        vuln_findings: Dict[str, Any],
        policy_evaluation: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> List[TextContent]:
        timestamp = datetime.utcnow().isoformat() + "Z"
        sbom_artifacts = sbom_data.get("artifacts", []) if isinstance(sbom_data, dict) else []
        vuln_summary = vuln_findings.get("summary", {}) if isinstance(vuln_findings, dict) else {}
        policy = policy_evaluation if isinstance(policy_evaluation, dict) else {}

        gates = {
            "no_critical_vulns": vuln_summary.get("by_severity", {}).get("CRITICAL", 0) == 0,
            "policy_allowed": policy.get("allow", False),
            "no_latest": not any("latest" in v.lower() for v in policy.get("violations", [])),
        }
        score = (sum(gates.values()) / len(gates)) * 100 if gates else 0
        status = "COMPLIANT" if score == 100 else ("WARNING" if score >= 75 else "NON_COMPLIANT")

        report = {
            "report_version": "1.0.0",
            "metadata": {
                "build_id": build_id,
                "image": image,
                "timestamp": timestamp,
                "scanner_versions": {
                    "syft": metadata.get("syft_version", "unknown"),
                    "trivy": metadata.get("trivy_version", "unknown"),
                    "opa": metadata.get("opa_version", "unknown"),
                },
            },
            "compliance": {"status": status, "score": score, "gates": gates},
            "sbom": {
                "total_packages": len(sbom_artifacts),
            },
            "vulnerabilities": vuln_summary,
            "policy": policy,
        }
        return [TextContent(type="text", text=json.dumps(report, indent=2))]

    async def generate_summary(self, report_data: Dict[str, Any]) -> List[TextContent]:
        compliance = report_data.get("compliance", {})
        policy = report_data.get("policy", {})
        vulnerabilities = report_data.get("vulnerabilities", {})
        summary = {
            "overall_status": compliance.get("status", "UNKNOWN"),
            "compliance_score": compliance.get("score", 0),
            "policy_allowed": policy.get("allow", False),
            "critical": vulnerabilities.get("by_severity", {}).get("CRITICAL", 0),
        }
        return [TextContent(type="text", text=json.dumps(summary, indent=2))]

    def _health(self) -> Dict[str, Any]:
        return {"status": "ok", "server": "report-server"}


async def main() -> None:  # pragma: no cover
    _setup_logging()
    server_instance = ReportServer()

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
                server_name="report-server",
                server_version="1.0.0",
                capabilities=capabilities,
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    if "--health" in sys.argv:
        data = ReportServer()._health()
        print(json.dumps(data))
        sys.exit(0 if data.get("status") == "ok" else 1)
    asyncio.run(main())  # pragma: no cover
