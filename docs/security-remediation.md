# September 2026 Security Remediation

This change addresses the 11 confirmed findings in the September 6, 2026
adversarial audit of baseline commit
`6d6e9d29760d79ab777b97b17cc941414081e93a`. It does not introduce authentication
or request/analyst activity logging. The original audit remains historical
evidence rather than a claim about the remediated code.

No AWS deployment, issue creation, credential rotation or
remote configuration change is part of this implementation. This work is published
to the feature branch with the 0.4.0 product-readiness changes. Historical AWS
identifiers in the deployment guide have not been revalidated.

## Finding Coverage

| Finding | Implemented control | Regression coverage |
| --- | --- | --- |
| F01: private GitHub metadata leakage | Anonymous public research/inventory requests; public search qualifier; explicit visibility checks before responses and shared caching. Server `GITHUB_TOKEN` is ignored. | Synthetic private repositories/issues excluded from initial and cached research; no authorization header on public reads. |
| F02: cross-package VEX suppression | Embedded claims retain CVE/component/version/file-instance scope. Approval never moves through the CVE summary. Conflicts remain unverified. Standalone VEX requires versioned package or immutable asset identity. | Mixed packages, same-named files, conflicting claims and name-only standalone VEX; real browser approval lowers only one package. |
| F03: false-clean scans | Explicit complete/partial/failed coverage; null counts for failure; unresolved detail IDs, pagination, malformed batches and inventory omissions disclosed. | Batch/detail failure, malformed rows, pagination and checked-clean results; browser failed counters and empty-state wording. |
| F04: omitted primary CVE identifiers | Group primary OSV CVE IDs together with CVE aliases. | Primary CVE without aliases survives normalization and repository grouping. |
| F05: forwarded-header quota bypass | Loopback proxy accepts one validated IP only. Nginx example overwrites XFF. Limiter state is capped and expired keys pruned. | Rotating caller-controlled prefixes in an appended chain still hit the same application limit. |
| F06: unbounded SBOM fallback/aggregation | JSON, XML, text and aggregation execute in one worker under shared work/output/depth/node budgets. Errors/timeouts terminate the worker and preserve current state. Component lookups are indexed by file instance and identity. | Malformed JSON, XML DTDs, valid XML, aggregate budget exhaustion and worker timeout; browser worker load failure and recovery. |
| F07: hidden inventory omissions | Raw-row/depth/query caps, unsupported versions and invalid schemas cannot appear complete. Versionless PURLs plus different versions are distinct identities. | Padded lockfile with late dependency, wildcard pins, invalid schema and two versions under one unversioned PURL. |
| F08: incomplete release verification | One archive contains Lambda, frontend/worker, IaC and per-file hashes. Provenance and manifest bind to the approved ref/commit. Deploy uses only extracted payloads. | Valid whole-bundle extraction; tampered, extra, missing, traversal, symlink, wrong-ref, wrong-commit, dirty, AppleDouble and noncanonical-path fixtures rejected before extraction. Local real bundle built and verified. |
| F09: lost monitor notifications | Pending notification persisted before SNS; stable event ID; conditional state revisions; baseline advances after acceptance only. Required-source failure preserves state. | SNS failure then retry publishes the same pending ID; source failure does not overwrite the baseline. |
| F10: issue-title suppression | Exact CVE candidates require explicit reuse; full body is previewed. Declining reuse prompts separately before creating a new issue. | Reuse/create/cancel branches checked offline. Browser cancellation makes no GitHub write and does not persist the token. |
| F11: spoofed official cloud sources | Parse HTTPS URLs and compare exact authorities/organization paths. Official references are not proof of service applicability. | Spoofed host suffix, query-embedded URL, credentials and lookalike GitHub organization rejected. |

## Verification

Run from the repository root:

```bash
npm ci --ignore-scripts
npm run verify
npm audit signatures
bash -n scripts/deploy-aws.sh
git diff --check
```

`verify` runs server/client syntax checks, builds the generated worker, runs the
existing security and parser suites, 11 adversarial regression groups, Python
archive-verification tests, and audits all npm dependencies. Regression network
and AWS transports are synthetic; the existing HTTP smoke suite requires a
temporary loopback listener.

Browser checks are now CI/release gates. Install Chromium, then run the test
runner, which starts and closes its own temporary loopback server:

```bash
npx playwright install chromium
npm run test:browser
```

Browser tests intercept external traffic. They exercise actual bundled workers,
JSON/XML import, file/approval isolation, preservation after failure, full issue
review, no-write cancellation, and failed scan states. Screenshots are generated
under ignored `.deploy/browser-checks/` at desktop, tablet and mobile widths.
The preview server itself is not put into mock research mode.

`npm run build:release` creates a local archive without touching AWS. An
uncommitted workspace is marked dirty and must never be represented as a
signed production release. The local manifest verifier can inspect it with
`--allow-dirty`; normal production deployment rejects it. Follow the
[deployment guide](deployment.md#deploy) for approved release handling.

## Operational Follow-Up

Local verification on September 6, 2026 used Node 26.8.1. Syntax/build checks,
both existing smoke suites, all adversarial groups, the release tests, and
Chromium workflows passed. npm reported zero known vulnerabilities; 40 installed
packages had verified registry signatures and 14 had verified attestations.
The real local release archive passed manifest/hash extraction checks with
explicit dirty-worktree allowance. Node 22 remains the CI/deployment target and
must be verified by CI before release; Docker and live AWS were not exercised.

- Restart old application processes and invalidate old research caches on a
  future deployment. If a private-capable GitHub token was previously used on an
  exposed server, review historical disclosure and revoke that token as needed;
  new code cannot undo earlier exposure.
- Protect `main`, release tags, workflow changes and deployment approvals in
  GitHub. The script checks the selected ref/commit but does not configure remote
  branch protection, prove that a human approved a release, or protect a
  compromised operator checkout.
- Verify signed release provenance in GitHub CI and validate the deployment in
  a separately authorized environment. Local checks do not attest an artifact,
  prove AWS IAM behavior, build the Docker image, or confirm SNS inbox delivery.
- Monitor delivery is at least once. SNS acceptance followed by a failed state
  acknowledgment can duplicate the stable event ID. Pending events have no TTL;
  resolve them before removing CVEs or monitor resources.
- Anonymous GitHub quotas, bounded OSV pages/details and unsupported lockfiles
  remain coverage limits. A complete scan refers to selected supported package
  records, not SAST, reachability or proof of runtime safety.
- VEX approval is an analyst decision, not issuer-signature verification. Version
  0.4.0 replaces batch import approval with dated, reversible target decisions.
  Imported claims remain unverified. Cloud source identity likewise does
  not establish account-specific service exposure.

## Highest-Value Next Checks

1. Run the new signed release workflow after review and verify its archive from a trusted checkout.
2. Exercise DynamoDB conditional writes and SNS retry/acknowledgment failures in a staging account.
3. Confirm branch/tag protection and release approval settings outside this repository.
4. Assess any historical private-token exposure before reusing an old deployment.

Authentication, tenant isolation and activity logging remain outside the agreed
scope. Do not use this unauthenticated application for shared confidential
case-management data.
