package security.policy

default allow = false

# Compute severity counts from Trivy JSON if summary is absent.
sev_count(sev) = n {
    results := input.vulnerabilities.Results
    n := count([1 | r := results[_]; v := r.Vulnerabilities[_]; v.Severity == sev])
} else = 0

computed_by_severity := {
    "LOW": sev_count("LOW"),
    "MEDIUM": sev_count("MEDIUM"),
    "HIGH": sev_count("HIGH"),
    "CRITICAL": sev_count("CRITICAL"),
}

computed_total := computed_by_severity["LOW"] + computed_by_severity["MEDIUM"] + computed_by_severity["HIGH"] + computed_by_severity["CRITICAL"]

vuln_summary := s {
    s := input.vulnerabilities.summary
} else := s {
    s := {"by_severity": computed_by_severity, "total_vulnerabilities": computed_total}
}

allow {
    no_latest_tags
    no_critical_vulnerabilities
    valid_base_image
}

no_latest_tags {
    not contains(input.image, ":latest")
}

no_critical_vulnerabilities {
    vuln_summary.by_severity.CRITICAL == 0
}

valid_base_image {
    approved := [
        "registry.access.redhat.com/ubi9",
        "registry.access.redhat.com/ubi8",
        "docker.io/library/alpine",
        "gcr.io/distroless"
    ]
    # Iterate approved list via indexing (avoids future.keywords.in requirement)
    startswith(input.image, approved[_])
}

violations[msg] {
    contains(input.image, ":latest")
    msg := "Image uses 'latest' tag, which is not allowed"
}

violations[msg] {
    vuln_summary.by_severity.CRITICAL > 0
    n := vuln_summary.by_severity.CRITICAL
    msg := sprintf("Image contains %d critical vulnerabilities", [n])
}

violations[msg] {
    not valid_base_image
    msg := "Image does not use an approved base image"
}

risk_level = "HIGH" {
    vuln_summary.by_severity.CRITICAL > 0
} else = "MEDIUM" {
    vuln_summary.by_severity.HIGH > 5
} else = "LOW" {
    vuln_summary.total_vulnerabilities > 0
} else = "NONE"
