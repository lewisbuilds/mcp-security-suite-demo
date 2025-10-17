#!/usr/bin/env python3
"""
End-to-end demo: SBOM → Vuln → Policy → Report
Uses the same underlying tools your MCP servers wrap.
Requires syft, trivy, opa on PATH (or set env vars below).
"""

import json
import os
import subprocess
import sys
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence, cast

IMAGE = os.environ.get("DEMO_IMAGE", "nginx:1.27")
SYFT = os.environ.get("SYFT_BIN", "syft")  # pinned in Dockerfiles, here we discover from PATH
TRIVY = os.environ.get("TRIVY_BIN", "trivy")
OPA = os.environ.get("OPA_BIN", "opa")
REPO_ROOT = Path(__file__).resolve().parents[1]

# Module-level logger
logger = logging.getLogger(__name__)


def _setup_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def run(cmd: Sequence[str], **kw: Any) -> str:
    r = subprocess.run(cmd, text=True, capture_output=True, **kw)
    if r.returncode != 0:
        logger.error(
            "Command failed: %s\nstdout:\n%s\nstderr:\n%s",
            " ".join(cmd),
            r.stdout,
            r.stderr,
        )
        raise SystemExit(f"Command failed: {' '.join(cmd)}")
    return cast(str, r.stdout)


def syft_sbom(image: str) -> Dict[str, Any]:
    out = run([SYFT, "-o", "json", image])
    return cast(Dict[str, Any], json.loads(out))


def trivy_vulns(image: str) -> Dict[str, Any]:
    # Allow non-zero exit when vulns found by adding "|| true" equivalent
    r = subprocess.run(
        [
            TRIVY,
            "image",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            image,
        ],
        text=True,
        capture_output=True,
    )
    if r.returncode not in (0, 1):  # trivy returns 1 when vulns found
        logger.error(
            "Trivy failed (rc=%s)\nstdout:\n%s\nstderr:\n%s", r.returncode, r.stdout, r.stderr
        )
        raise SystemExit("Trivy failed")
    logger.debug("Trivy completed (rc=%s)", r.returncode)
    return cast(Dict[str, Any], json.loads(r.stdout or "{}") or {})


def policy_eval(input_doc: Dict[str, Any]) -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
        json.dump(input_doc, f)
        f.flush()
        data_file = str(REPO_ROOT / "servers/policy/policy.rego")
        out = run(
            [
                OPA,
                "eval",
                "--format",
                "json",
                "--input",
                f.name,
                "--data",
                data_file,
                "data.security.policy",
            ]
        )
    data = json.loads(out)
    res: List[Dict[str, Any]] = data.get("result") or []
    if res and isinstance(res, list) and res[0].get("expressions"):
        value = res[0]["expressions"][0].get("value", {})
    else:
        value = {}
    return {
        "allow": bool(value.get("allow")),
        "violations": value.get("violations", []),
        "risk_level": value.get("risk_level", "UNKNOWN"),
    }


def aggregate(
    build_id: str, image: str, sbom: Dict[str, Any], vuln: Dict[str, Any], policy: Dict[str, Any]
) -> Dict[str, Any]:
    # Approx counts
    results = vuln.get("Results") or []
    crit = 0
    high = 0
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity")
            if sev == "CRITICAL":
                crit += 1
            if sev == "HIGH":
                high += 1

    # Simple “changed packages” vs empty baseline
    pkgs = [f"{p.get('name')}@{p.get('version')}" for p in sbom.get("artifacts", [])]
    report = {
        "build_id": build_id,
        "image": image,
        "vulns": {"critical": crit, "high": high, "total": crit + high},
        "sbom_packages_sample": pkgs[:25],
        "policy": policy,
        "status": "PASS" if policy.get("allow") and crit == 0 else "FAIL",
    }
    return report


def main() -> None:
    _setup_logging()
    build_id = os.environ.get("DEMO_BUILD_ID", "local-001")
    # Avoid non-ASCII emoji for Windows consoles without UTF-8 code page
    logger.info("Image: %s", IMAGE)
    sbom = syft_sbom(IMAGE)
    vuln = trivy_vulns(IMAGE)

    # Policy expects full image string and raw vulnerabilities; it will compute summary.
    policy_input = {"image": IMAGE, "vulnerabilities": vuln}
    policy = policy_eval(policy_input)

    report = aggregate(build_id, IMAGE, sbom, vuln, policy)

    out = Path("demo-report.json")
    out.write_text(json.dumps(report, indent=2))
    logger.info("Wrote %s", out)
    logger.debug(
        "Report summary: status=%s crit=%s high=%s",
        report.get("status"),
        report.get("vulns", {}).get("critical"),
        report.get("vulns", {}).get("high"),
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
