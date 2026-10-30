---
description: 'Use the four scoped GitHub Actions and release skills for existing and future pipelines.'
applyTo: '.github/workflows/**, .github/actions/**, **/action.yml, **/action.yaml, **/pipeline*/**, **/release*/**, **/CHANGELOG.md'
---
# GitHub Actions and release conventions

Before creating or editing a pipeline, inspect repository guidance, workflow triggers,
required checks, supported platforms, release policy and relevant recent run evidence.
Read only the applicable skills and needed references under `.github/skills/`:

- `github-actions-efficiency/SKILL.md`: pipeline creation, caches, concurrency,
  trigger scoping, matrix design, runtime and CI cost.
- `github-actions-hardening/SKILL.md`: every new or changed Actions workflow;
  review trust boundaries, script injection, least privilege, immutable pins,
  secrets, artifacts/caches and runner exposure.
- `github-actions-runtime-upgrade-conventions/SKILL.md`: action version changes
  or runtime deprecations; verify current compatible releases and runner support.
- `github-release/SKILL.md`: preparing an actual release, version or changelog.
  Follow the repository's packaging model; do not force a single-package
  procedure onto monorepos, deployment-only or non-versioned projects.

Preserve existing repository rules and explicit user authorization. Loading a skill
does not authorize a release, tag, merge, deployment, permission change or schedule.
Resolve a real rule conflict explicitly; never weaken a quality gate to obtain green CI.

Measure efficiency before changing behavior. Keep required checks runnable, preserve
release/schema/migration/shared-library validation and documented compatibility.
Cancel superseded validation only where safe; never cancel active release or deployment
work indiscriminately. Distinguish measured savings from estimates.

Resolve action versions from authoritative upstream releases; use verified full commit
SHAs with version comments. Example pins in skills are illustrative, not current versions.
Never force a newer Node runtime using an environment override as a substitute for a
compatible action upgrade. Review runner requirements and outputs, then validate the
affected workflow. Do not run privileged publishing steps merely to test an upgrade.

For a new pipeline, define the smallest stack-appropriate baseline first. Do not add
empty workflows, speculative matrices, automatic releases or maintenance schedules.
For every change, record rationale, validation, remaining gaps and rollback implications.
Static review is not live-run proof. This guidance does not itself enforce CI gates.

Vendored skills are locked in `.github/awesome-copilot-actions-lock.json`.
Refresh deliberately from the pinned source, preserving local adaptations and license.
