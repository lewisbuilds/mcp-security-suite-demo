#!/usr/bin/env python3
"""
Chain CLI: SBOM -> Vuln -> Policy -> Report
Produces sbom.json, vuln.json, policy.json, demo-report.json in CWD.
Pins align with CI and Dockerfiles. Trivy exit code 1 is treated as non-fatal.
"""

import argparse
import json
import os
import subprocess
import sys
import logging
from pathlib import Path
from typing import Any, Dict, Sequence, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = os.environ.get("DEMO_IMAGE", "nginx:1.27")
SYFT = os.environ.get("SYFT_BIN", "syft")
TRIVY = os.environ.get("TRIVY_BIN", "trivy")
OPA = os.environ.get("OPA_BIN", "opa")

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


def run_checked(cmd: Sequence[str], **kw: Any) -> str:
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


def syft_sbom(image: str, out_path: Path) -> None:
    data = run_checked([SYFT, "-o", "json", image])
    out_path.write_text(data)
    logger.info("Wrote %s", out_path)


def trivy_vulns(image: str, out_path: Path) -> None:
    r = subprocess.run(
        [
            TRIVY,
            "image",
            "--format",
            "json",
            "--severity",
            "HIGH,CRITICAL",
            "--no-progress",
            image,
        ],
        text=True,
        capture_output=True,
    )
    if r.returncode not in (0, 1):
        logger.error(
            "Trivy failed (rc=%s)\nstdout:\n%s\nstderr:\n%s", r.returncode, r.stdout, r.stderr
        )
        raise SystemExit("Trivy failed")
    out_path.write_text(r.stdout or "{}")
    logger.info("Wrote %s (rc=%s)", out_path, r.returncode)


def aggregate(
    build_id: str,
    image: str,
    sbom: Dict[str, Any],
    vuln: Dict[str, Any],
    policy_eval: Dict[str, Any],
) -> Dict[str, Any]:
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
    pkgs = [f"{p.get('name')}@{p.get('version')}" for p in sbom.get("artifacts", [])]
    status = (
        "PASS"
        if crit == 0 and (policy_eval.get("allow") if isinstance(policy_eval, dict) else True)
        else "FAIL"
    )
    return {
        "build_id": build_id,
        "image": image,
        "vulns": {"critical": crit, "high": high, "total": crit + high},
        "sbom_packages_sample": pkgs[:25],
        "policy": policy_eval,
        "status": status,
    }


def main() -> None:
    _setup_logging()
    ap = argparse.ArgumentParser(description="Run SBOM -> Vuln -> Policy -> Report chain")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--build-id", default=os.environ.get("BUILD_ID", "local-001"))
    args = ap.parse_args()

    image = args.image
    print(f"[chain] image={image}")

    sbom_p = Path("sbom.json")
    vuln_p = Path("vuln.json")
    policy_p = Path("policy.json")
    report_p = Path("demo-report.json")

    # SBOM
    data = run_checked([SYFT, "-o", "json", image])
    sbom_p.write_text(data)
    print(f"[chain] wrote {sbom_p}")
    logger.debug("Wrote SBOM to %s", sbom_p)

    # Vulns (allow code 1)
    r = subprocess.run(
        [
            TRIVY,
            "image",
            "--format",
            "json",
            "--severity",
            "HIGH,CRITICAL",
            "--no-progress",
            image,
        ],
        text=True,
        capture_output=True,
    )
    if r.returncode not in (0, 1):
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit("Trivy failed")
    vuln_p.write_text(r.stdout or "{}")
    print(f"[chain] wrote {vuln_p}")
    logger.debug("Wrote vulns to %s", vuln_p)

    sbom = json.loads(sbom_p.read_text() or "{}")
    vuln = json.loads(vuln_p.read_text() or "{}")

    policy_input = {"image": image, "vulnerabilities": vuln}

    # Evaluate policy gate via OPA (direct call for normalized output)
    opa_out = run_checked(
        [
            OPA,
            "eval",
            "--format",
            "json",
            "--input",
            "-",
            "--data",
            str(REPO_ROOT / "servers/policy/policy.rego"),
            "data.security.policy",
        ],
        input=json.dumps(policy_input),
    )
    try:
        value = json.loads(opa_out).get("result", [{}])[0].get("value", {})
        policy_norm = {
            "allow": bool(value.get("allow")),
            "violations": value.get("violations", []),
            "risk_level": value.get("risk_level", "UNKNOWN"),
        }
    except Exception:
        policy_norm = {
            "allow": False,
            "violations": ["policy_evaluation_error"],
            "risk_level": "UNKNOWN",
        }

    policy_p.write_text(json.dumps(policy_norm, indent=2))
    print(f"[chain] wrote {policy_p}")
    logger.debug("Wrote policy to %s", policy_p)

    report = aggregate(args.build_id, image, sbom, vuln, policy_norm)
    report_p.write_text(json.dumps(report, indent=2))
    print(f"[chain] wrote {report_p}")
    logger.debug("Wrote report to %s", report_p)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()  # pragma: no cover
