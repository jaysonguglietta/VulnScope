# Changelog

## Unreleased

- Add bounded public GitHub dependency-graph scanning with OSV CVE matching.
- Fall back to bounded public lockfile inspection when GitHub's generated SBOM is unavailable.
- Add analyst confirmation, duplicate checks, prefilled issue drafts, and direct
  GitHub issue publishing with an ephemeral fine-grained token.

## 0.3.0 - 2026-08-11

Security hardening release for VulnScope's public research API, browser evidence
workflows, vulnerability matching, exports, AWS infrastructure, and release
pipeline.

### Security

- Bound OSV enrichment fan-out, upstream concurrency, response bytes, deadlines,
  cache growth, API capacity, and public-origin access.
- Require analyst-approved, exact-product VEX matches before suppressive claims
  can lower exposure priority.
- Neutralize spreadsheet formulas in CSV exports while preserving typed numbers
  and booleans.
- Move cloud and VEX evidence parsing into a fail-closed worker with explicit
  file, row, nesting, dimension, cell, and expansion budgets.
- Bind OSV fixed versions and affected ranges to the queried package instead of
  returning fixes from unrelated package entries.
- Reject invalid upstream dates and encode every rendered date value.
- Add immutable action and container references, dependency signature checks,
  release checksums, SPDX SBOM generation, and GitHub build provenance.
- Manage deployment artifacts and Lambda log retention in CloudFormation,
  tighten log-write IAM resources, and scan infrastructure in CI.
- Add AWS managed known-bad-input WAF protection alongside API rate limiting.

### Deployment

- Production AWS deployment now requires a checksum-verified, GitHub-attested
  Lambda artifact by default.
- Set `ALLOW_LOCAL_UNSIGNED_BUILD=1` only for a documented emergency deployment.
- Deployment artifacts expire after 30 days by default; Lambda logs are retained
  for 30 days.

### Fixed Issues

- [#1](https://github.com/jaysonguglietta/VulnScope/issues/1)
- [#2](https://github.com/jaysonguglietta/VulnScope/issues/2)
- [#3](https://github.com/jaysonguglietta/VulnScope/issues/3)
- [#4](https://github.com/jaysonguglietta/VulnScope/issues/4)
- [#5](https://github.com/jaysonguglietta/VulnScope/issues/5)
- [#6](https://github.com/jaysonguglietta/VulnScope/issues/6)
- [#7](https://github.com/jaysonguglietta/VulnScope/issues/7)
- [#8](https://github.com/jaysonguglietta/VulnScope/issues/8)
