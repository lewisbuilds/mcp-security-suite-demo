## Policy Module

Open Policy Agent (OPA) Rego policy used to evaluate container images for basic supply chain hygiene:

Key checks:
1. Image must NOT use the `:latest` tag.
2. Base image must be one of the approved prefixes (UBI8/9, Alpine, Distroless).
3. No critical vulnerabilities (uses summary if supplied; otherwise computes counts from raw Trivy results).
4. Derived `risk_level` classification (HIGH > CRITICAL present, MEDIUM > many HIGH, LOW > any remaining vulns, NONE otherwise).

### Running Unit Tests

The Rego unit tests live in `policy_test.rego` and are executed automatically in CI.

Run locally (requires OPA binary on PATH):

```bash
opa test servers/policy -v
```

### Evaluating the Policy Manually

Given an input JSON formatted like the CI-produced `policy-input-<build>.json`:

```bash
opa eval --data servers/policy/policy.rego --input policy-input.json 'data.security.policy'
```

### Notes

The policy will compute a vulnerability summary if `input.vulnerabilities.summary` is absent by iterating raw Trivy result objects. This keeps the evaluation flexible across different pipeline stages.

### Health & Logging

- Health (JSON to stdout, exit code reflects status):

```bash
python -m servers.policy.app --health
```

- Logging can be configured with environment variables:
	- `LOG_FORMAT=json` for structured JSON logs
	- `LOG_LEVEL=DEBUG|INFO|WARNING|ERROR`
