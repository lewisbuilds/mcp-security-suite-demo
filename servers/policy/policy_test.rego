package security.policy

# Rego unit tests for policy rules.
# These tests validate:
# - Summary computation fallback when no summary provided
# - Allow rule conditions (no latest tag, approved base image, no critical vulns)
# - Violations messages for disallowed conditions
# - risk_level derivation across scenarios

############################################
# Helpers
############################################

# Minimal vulnerability object constructor for convenience
vuln(sev) = {"Severity": sev}

############################################
# Tests: allow rule
############################################

test_allow_passes_when_all_conditions_met {
  input := {
    "image": "registry.access.redhat.com/ubi9:1.0",
    "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0}, "total_vulnerabilities": 3}}
  }
  allow with input as input
}

test_allow_denied_with_latest_tag {
  input := {
    "image": "registry.access.redhat.com/ubi9:latest",
    "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 0}}
  }
  not allow with input as input
  some m
  violations[m] with input as input
  m == "Image uses 'latest' tag, which is not allowed"
}

test_allow_denied_with_critical_vulnerability {
  input := {
    "image": "registry.access.redhat.com/ubi9:1.0",
    "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 2}}
  }
  not allow with input as input
  some m
  violations[m] with input as input
  m == "Image contains 2 critical vulnerabilities"
}

test_allow_denied_with_unapproved_base_image {
  input := {
    "image": "docker.io/library/ubuntu:22.04",
    "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 0}}
  }
  not allow with input as input
  some m
  violations[m] with input as input
  m == "Image does not use an approved base image"
}

############################################
# Tests: summary computation fallback
############################################

test_summary_is_computed_when_absent {
  # Provide raw Trivy-like structure (subset) without summary; expect CRITICAL count=1, HIGH=1, MEDIUM=0, LOW=0
  input := {
    "image": "registry.access.redhat.com/ubi9:1.0",
    "vulnerabilities": {
      "Results": [
        {"Vulnerabilities": [vuln("HIGH"), vuln("CRITICAL")]} 
      ]
    }
  }
  vuln_summary.by_severity.CRITICAL == 1 with input as input
  vuln_summary.by_severity.HIGH == 1 with input as input
  vuln_summary.by_severity.MEDIUM == 0 with input as input
  vuln_summary.by_severity.LOW == 0 with input as input
  vuln_summary.total_vulnerabilities == 2 with input as input
}

############################################
# Tests: risk_level derivation
############################################

test_risk_level_high_when_critical_present {
  input := {"image": "registry.access.redhat.com/ubi9:1.0", "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 1}}}
  risk_level == "HIGH" with input as input
}

test_risk_level_medium_when_many_high {
  input := {"image": "registry.access.redhat.com/ubi9:1.0", "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 6, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 6}}}
  risk_level == "MEDIUM" with input as input
}

test_risk_level_low_when_only_low_medium {
  input := {"image": "registry.access.redhat.com/ubi9:1.0", "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 3}, "total_vulnerabilities": 5}}}
  risk_level == "LOW" with input as input
}

test_risk_level_none_when_no_vulnerabilities {
  input := {"image": "registry.access.redhat.com/ubi9:1.0", "vulnerabilities": {"summary": {"by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "total_vulnerabilities": 0}}}
  risk_level == "NONE" with input as input
}
