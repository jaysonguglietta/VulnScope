# VulnScope Deployment Notes

Configured domain: `https://vulnscope.jsontechnology.com`

Deployment status is unverified. The resource identifiers below are historical;
this local remediation pass has not queried AWS, recreated removed resources,
deployed code, or changed billing alarms. Confirm the intended account and live
resource inventory before a future deployment.

VulnScope uses a serverless AWS deployment for very light traffic. Authentication and request logging are intentionally excluded. The production boundary is public research with browser-local, non-sensitive analyst data.

## Architecture

```text
Browser
  -> Route 53: vulnscope.jsontechnology.com
  -> CloudFront: TLS, security headers, method controls, WAF rate limit
     -> private S3 origin: HTML, CSS, JavaScript, browser worker
     -> API Gateway HTTP API
        -> vulnscope-api Lambda
           -> public vulnerability-intelligence sources

Optional EventBridge schedule
  -> vulnscope-monitor Lambda
     -> public vulnerability-intelligence sources
     -> encrypted DynamoDB snapshots with 180-day TTL
     -> SNS email for material changes
```

Raw SBOM, cloud, and VEX files remain in browser memory. The backend receives a CVE ID for research or, after explicit confirmation, a bounded set of normalized package identifiers for OSV enrichment. Public repository scanning sends a validated GitHub owner/repository name to the backend, which reads GitHub's public generated SBOM or supported public lockfiles and sends exact package versions to OSV. GitHub issue publishing bypasses the backend: the browser sends an analyst-provided token directly to `api.github.com`.

## Historical Resource Inventory

- AWS account: `171058045575`
- Region: `us-east-1`
- CloudFormation stack: `vulnscope-prod`
- Artifact CloudFormation stack: `vulnscope-artifacts`
- Hosted zone: `jsontechnology.com` / `ZE0UTGIT9KUYU`
- Domain: `vulnscope.jsontechnology.com`
- CloudFront distribution: `E19BTXYV3YQQSQ`
- CloudFront domain: `d306xsajqlo259.cloudfront.net`
- API Gateway endpoint: `https://0itdu9uhqc.execute-api.us-east-1.amazonaws.com`
- API Lambda: `vulnscope-api`
- Static bucket: `vulnscope-jsontechnology-com-171058045575`
- Artifact bucket: `vulnscope-artifacts-171058045575-us-east-1`
- ACM certificate: `arn:aws:acm:us-east-1:171058045575:certificate/41e49f5a-74e5-4901-ba91-f81a998a2183`
- Billing SNS topic: `arn:aws:sns:us-east-1:171058045575:vulnscope-cost-alerts`
- Billing alarms: `VulnScope-Monthly-EstimatedCharges-10USD` and `VulnScope-Monthly-EstimatedCharges-20USD`

Previously recorded estimated-charge alarms were configured to send to `Jayson.Guglietta@gmail.com`. Billing metrics and alarms are in `us-east-1`.

Scheduled-monitor resources are conditional. When enabled, the stack adds `vulnscope-monitor`, an EventBridge rule, an encrypted on-demand DynamoDB table, and a dedicated SNS topic/subscription. Read their generated identifiers from CloudFormation outputs and resources rather than assuming fixed ARNs.

## Deploy

From the repository root:

```bash
npm run verify
```

Prerequisites: Node 22, npm, Python 3, Git, zip/tar, OpenSSL, AWS CLI, and a GitHub
CLI supporting source-ref/source-digest attestation checks. Use a reviewed checkout
for the local deploy script and verifier; those are part of the operator trust
boundary.

Run the GitHub `Release artifact` workflow on an approved version tag (`v*`) or
`main`. Download its `vulnscope-<commit>` artifact without unpacking the inner
`deployment.tar.gz`. Record the approved 40-character commit, full ref and bundle
checksum from the reviewed release. Set these variables for all deployment
commands below:

```bash
export DEPLOYMENT_BUNDLE_PATH="$PWD/release/deployment.tar.gz"
export DEPLOYMENT_BUNDLE_SHA256="<approved 64-character bundle SHA-256>"
export RELEASE_SOURCE_SHA="<approved 40-character commit>"
export RELEASE_SOURCE_REF="refs/tags/<approved v-prefixed tag>"
npm run deploy:aws
```

For a reviewed build from main, use `RELEASE_SOURCE_REF=refs/heads/main`. Do not
substitute the current local HEAD or branch for the release identity.

The script verifies GitHub-signed provenance against the repository, pinned
workflow path, approved source ref and commit, and rejects self-hosted builders.
These policy flags are documented in the [GitHub CLI attestation verifier](https://cli.github.com/manual/gh_attestation_verify).
It also verifies the archive checksum, manifest identity and every file hash
before extracting into a private temporary directory. Unsafe paths, links,
extra/missing files, and dirty source manifests are rejected.

The archive contains `lambda.zip` (including `lib/` and the shared research model), all `public/` assets including the generated
app and SBOM worker, both `infra/` templates, and `release.json`. Deployment reads only
those extracted payloads. It never syncs frontend files or templates from the
operator's checkout. Deployment parameters, account selection, credentials, and
the local verifier remain trusted operator inputs.

The workflow uses pinned actions, `npm ci --ignore-scripts`, dependency audits,
registry signature verification, and offline Chromium workflow tests. It builds the app, worker and Lambda, emits an
SPDX Lambda dependency SBOM, and attests the complete archive plus SBOM.
The SBOM is Lambda-scoped; frontend build provenance is covered by the archive,
not a separate frontend SBOM.

Unsigned local builds are refused by default.
`ALLOW_LOCAL_UNSIGNED_BUILD=1 npm run deploy:aws` is an explicit break-glass
path when no bundle path is provided. It builds local sources, including any
uncommitted changes, so it has no approved-release provenance guarantee. Use
only with a separately authorized change record. To build without touching AWS,
run `npm run build:release`; it writes under ignored `.deploy/`.

Defaults:

```bash
AWS_REGION=us-east-1
AWS_PROFILE=json
EXPECTED_AWS_ACCOUNT_ID=171058045575
STACK_NAME=vulnscope-prod
DOMAIN_NAME=vulnscope.jsontechnology.com
ROOT_DOMAIN=jsontechnology.com
```

The script refuses to deploy when the resolved account differs from `EXPECTED_AWS_ACCOUNT_ID`. This prevents an accidentally selected AWS profile from creating the production names in another account.

The deploy script generates a 256-bit origin-verification secret for CloudFront and Lambda. Set `ORIGIN_VERIFY_SECRET` explicitly when deployments must retain the same value; otherwise each deployment rotates it. The value is a `NoEcho` CloudFormation parameter and is never sent to the browser.

The script:

1. Verifies the complete release bundle, source-bound provenance and per-file manifest, or builds locally only through explicit break-glass authorization.
2. Resolves the AWS account and public Route 53 hosted zone.
3. Deploys the verified bundle's `infra/vulnscope-artifacts.yml`, which owns the private, encrypted, versioned artifact bucket and its lifecycle policy.
4. Uploads the bundled Lambda artifact and deploys the bundled `infra/vulnscope.yml`.
5. Syncs only the bundled `public/` to the private static bucket and invalidates CloudFront.

Deploy another environment only with intentional overrides:

```bash
STACK_NAME=vulnscope-dev \
DOMAIN_NAME=vulnscope-dev.jsontechnology.com \
npm run deploy:aws
```

For another AWS account, also set that account's profile and expected account ID explicitly.

## Scheduled Monitoring

Monitoring is disabled unless both `NOTIFICATION_EMAIL` and `MONITORED_CVES` are non-empty.

```bash
NOTIFICATION_EMAIL=Jayson.Guglietta@gmail.com \
MONITORED_CVES=CVE-2021-44228,CVE-2023-22527 \
MONITOR_SCHEDULE='rate(1 day)' \
npm run deploy:aws
```

Confirm the SNS subscription email after the first deployment. The initial execution creates baselines and does not alert. Later executions alert only on material changes, including:

- New CISA KEV membership
- Changed risk, real-world, exploitation, exploit-maturity, or patch status
- EPSS increase of at least 0.10
- Increased public exploit-code evidence
- At least three new evidence items

Delivered baselines expire after 180 days. Before SNS publication, each material
change is saved as a pending notification with a stable event ID and a
conditional revision. Pending changes have no TTL, are retried before new
research, and advance the baseline only after SNS accepts the publication.
Required CVE, KEV or EPSS lookup failure preserves the previous baseline and
fails the invocation. Older snapshot-only records are read compatibly.

Delivery is at least once: SNS acceptance followed by a failed DynamoDB
acknowledgment can yield a duplicate carrying the same event ID. SNS acceptance
does not prove that an email reached the inbox. Confirm subscriptions and check
Lambda errors and pending records during operational validation. Pending
records for removed CVEs are not drained automatically; resolve them before
removing the CVE or explicitly accept their removal. No new activity logging or
alarm resources are added here.

Update the CVE list by redeploying with the complete desired comma-separated list. Disable monitoring by deploying with empty `NOTIFICATION_EMAIL` and `MONITORED_CVES`; CloudFormation removes the conditional resources.

The browser watchlist is intentionally local and is not synchronized to the scheduled monitor because the application has no authenticated user account or server-side case store.

### Operator Configuration and Status

**Data and operations** exports the chosen email, explicit 1-25 CVE subset and
verified-release prerequisites as JSON. The app does not execute that artifact,
deploy resources or send confirmation emails. The monitor rejects invalid lists
and lists exceeding 25 rather than silently discarding entries. Empty lists
remain the explicit disabled configuration.

After a separately approved deployment, this read-only check verifies account,
stack state, scheduled rule, function configuration and SNS confirmation counts:

```bash
AWS_PROFILE=json AWS_REGION=us-east-1 STACK_NAME=vulnscope-prod \
EXPECTED_AWS_ACCOUNT_ID=171058045575 npm run monitor:status
```

The output excludes credentials, origin secrets and subscriber email addresses.
`disabled`, `pending` subscriptions, Lambda state and schedule state are separate.
The script never invokes the monitor. Missing credentials/resources leave status
unverified rather than healthy. For delivery diagnosis, inspect Lambda
Invocations/Errors metrics and the intended CVE keys in the monitor table:
`pending.eventId` indicates an unresolved publication; `snapshot.checkedAt`
dates the accepted baseline. Check an authorized recipient inbox separately.
Neither a confirmed subscription nor SNS acceptance proves inbox delivery.

## API Contract and Limits

Production exposes only:

- `GET /api/health`
- `GET /api/research?cve=CVE-YYYY-NNNN[&refresh=1]`
- `POST /api/enrich`
- `POST /api/github/scan`

CloudFront requires its full seven-method origin behavior whenever `POST` is enabled. The effective application allowlist is the four explicit API Gateway routes above; `PUT`, `PATCH`, `DELETE`, and unknown paths have no API Gateway route and do not invoke the Lambda.

The enrichment request is JSON and accepts no more than 50 package records per request. Repository inventory retains at most 500 identities; callers explicitly continue later batches. Public GitHub scans accept only canonical HTTPS repository URLs, reject private repositories and inspect at most 20,000 generated-SBOM rows. Asynchronous generation can return `pending` plus a repository-bound UUID; resend the same URL and `jobId` to resume. Downloads use validated HTTPS GitHub hosts with at most three redirects. If the API is unavailable (404/410), or the user explicitly chooses fallback, the scanner inspects up to 50,000 tree entries and 10 supported public lockfiles, with a 4 MiB decoded limit per file and 16 MiB aggregate inventory budget. Supported formats and recovery are in [repository scanning](github-repository-scanning.md).

API bodies are capped at 256 KiB. OSV hydration is limited to 40 advisory details, 41 outbound calls and 32 MiB aggregate response data per request; individual responses are at most 8 MiB. `pageToken` and `detailOffset` continue each package's query, and failed details remain unresolved. Queues and outbound stages share a **17-second overall API deadline**, below the template's 20-second API Lambda timeout. Individual stages can use up to 15 seconds, but never beyond the remaining overall budget. The browser resumes work through new requests, not a long-running Lambda. Warm instances cache up to 500 OSV details for an hour. These bounds are tested offline, not a live AWS latency guarantee.

Example repository scan:

```bash
curl -sS -X POST https://vulnscope.jsontechnology.com/api/github/scan \
  -H 'content-type: application/json' \
  --data '{"url":"https://github.com/jaysonguglietta/VulnScope"}'
```

The response includes normalized repository metadata, inventory counts,
package-specific OSV results, `status` (`pending`, `complete`, `partial`, `failed`),
`coverage` (checked package count, reasons, unresolved advisory IDs), `truncated`,
and source results. The UI groups primary IDs and aliases by CVE. OSV failure
returns unknown counts, not a clean zero. Unconsumed pagination, hydration or
inventory omissions remain partial even with HTTP 200.

Automatic issue publishing does not use the Lambda API. The browser sends the analyst-provided, fine-grained token directly to `https://api.github.com`, shows the full draft body, checks exact CVE-title candidates, requires explicit reuse or a separate new-issue confirmation, creates confirmed issues sequentially, and does not persist the token. Limit the token to the destination repository with **Issues: Read and write** and a short expiration. The UI caps each publishing batch at 10 confirmed CVEs. The production CSP permits that single additional connection origin.

Repository scan limits are configurable for local and alternative deployments:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `GITHUB_REPOSITORY_PACKAGE_MAX` | `50` | Default parser query limit; repository discovery explicitly retains up to 500 and enrichment queries 50 per request |
| `API_DEADLINE_MS` | `17000` | Overall API budget; configurable downward, capped at 17 seconds |
| `GITHUB_REPOSITORY_SBOM_INSPECT_MAX` | `20000` | Generated-SBOM or lockfile records inspected |
| `GITHUB_REPOSITORY_TREE_INSPECT_MAX` | `50000` | Default-branch tree entries inspected |
| `GITHUB_REPOSITORY_LOCKFILE_MAX` | `10` | Supported lockfiles fetched |
| `GITHUB_REPOSITORY_LOCKFILE_MAX_BYTES` | `4194304` | Maximum decoded bytes per lockfile |
| `GITHUB_REPOSITORY_INVENTORY_MAX_BYTES` | `16777216` | Aggregate GitHub inventory response budget |
| `GITHUB_REPOSITORY_INVENTORY_DEADLINE_MS` | `15000` | GitHub inventory deadline |

Increasing these values raises Lambda duration, OSV fan-out, GitHub API use, and
abuse-cost exposure. Keep the OSV and outbound budgets aligned when changing the
package maximum.

The CloudFront WAF blocks an IP after 100 requests in a five-minute evaluation window for `/api/` paths. API Gateway throttles the stage to 2 requests per second with a burst of 5. The API Lambda has reserved concurrency 2; the optional monitor has reserved concurrency 1. Application-level queues and rate limits provide an additional bound.

CloudFront adds `X-Origin-Verify` only on the API origin request. Lambda requires that value in AWS, preventing the documented API Gateway hostname from bypassing CloudFront and its WAF. Local and container deployments do not require the header unless `ORIGIN_VERIFY_SECRET` is configured.

Lambda uses API Gateway's `requestContext.http.sourceIp` as its trusted rate-limit identity. For a local reverse-proxy deployment, forwarded addresses are accepted only when `TRUST_PROXY=1`, the direct peer is loopback, and the header contains exactly one syntactically valid IP. Comma-separated chains are rejected. Limiter storage is capped at 2,000 clients; at capacity, new identities receive 429 until entries expire.

## Storage and Retention

- Static bucket: private OAC access, AES-256 encryption, versioning, noncurrent versions deleted after 7 days.
- Artifact bucket: retained CloudFormation resource with public access blocked, AES-256 encryption, ownership enforcement, versioning, incomplete-upload cleanup after 1 day, noncurrent-version cleanup after 7 days, and artifact expiration after 30 days by default.
- Browser uploads: memory only; cleared on refresh or by the user.
- Ordinary repository scan results: session memory. Confirmed review snapshots, selected CVEs and filing receipts persist in IndexedDB. Issue tokens are memory-only and excluded from all storage/export paths.
- Browser cases, watches and local decisions: per-record IndexedDB transactions/revisions; no automatic expiration or capacity eviction. Legacy localStorage records are migrated without deleting the original keys. Browser eviction/profile loss is still possible; use backups.
- Versioned workspace backups: unencrypted local files, at most 20 MiB. Normalized inventory is opt-in. Restore previews merge/replace, rejects incompatible formats, and resets approvals and imported filing outcomes to unverified.
- Monitor baselines: encrypted DynamoDB; TTL after 180 days when no notification is pending. Pending notifications have no TTL until acknowledged or deliberately removed.
- Lambda log groups: explicitly managed with 30-day retention and function-scoped write permissions.

## Production Validation

```bash
curl -I https://vulnscope.jsontechnology.com/
curl -sS https://vulnscope.jsontechnology.com/api/health
curl -sS 'https://vulnscope.jsontechnology.com/api/research?cve=CVE-2023-22527'
curl -sS -X POST https://vulnscope.jsontechnology.com/api/github/scan \
  -H 'content-type: application/json' \
  --data '{"url":"https://github.com/jaysonguglietta/VulnScope"}'
curl -i -X POST https://vulnscope.jsontechnology.com/api/research
```

Expected behavior:

- Static content returns CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer Policy, and Permissions Policy.
- Health reports source states truthfully as observed, optional, or not yet checked.
- Valid research returns JSON; invalid CVE IDs return `400`.
- A valid public repository returns inventory and source results; malformed,
  non-GitHub, private, or extra-path repository URLs fail without an arbitrary
  outbound request.
- A method not present in API Gateway returns `404`, while the local API handler returns `405` for a known route with a disallowed method.

Validate infrastructure before deployment:

```bash
aws cloudformation validate-template \
  --region us-east-1 \
  --template-body file://infra/vulnscope.yml
aws cloudformation validate-template \
  --region us-east-1 \
  --template-body file://infra/vulnscope-artifacts.yml
```

CI also runs pinned `cfn-lint` and Checkov versions. Checkov exceptions are kept
in the workflow for the documented low-cost choices: no request/access logging,
VPC, dead-letter queues, or customer-managed KMS resources. Findings outside
that explicit list fail the infrastructure job.

## Cost Model

For a few requests per day, this avoids continuously running compute:

- S3, CloudFront, and the CloudFront-associated WAF charge for storage, requests,
  data transfer, Web ACL/rule capacity, and evaluated web requests.
- HTTP API and Lambda charge per request/invocation.
- ACM public certificates have no separate certificate charge.
- Conditional DynamoDB, EventBridge, SNS, and monitor Lambda usage should remain small for a short CVE list and daily schedule.

The `$10` and `$20` alarms are account-level estimated-charge alarms, not hard spending limits. Unexpected traffic can accrue charges before an email is read. The current template includes a CloudFront WAF rate-based rule and AWS managed known-bad-input rule group. API Gateway throttling, Lambda concurrency, and application limits provide additional abuse-cost controls.

## Source Tokens

Optional `NVD_API_KEY` and `VULNCHECK_API_TOKEN` values can improve source coverage
or rate limits. Public GitHub research and inventory requests are anonymous;
server-side `GITHUB_TOKEN` is ignored. GitHub search results must be public and
visibility-verifiable before being returned or cached. Anonymous quota
exhaustion degrades coverage rather than broadening token access.

The analyst issue token is entered only in the browser, restricted to the
selected repository with **Issues: Read and write**, and must not be configured
as a server environment variable.

Never commit source tokens or add them to frontend files. For production, use
Secrets Manager or another approved secret-injection path and tightly scoped
IAM. The current template does not provision those secrets.

## Evidence Inputs

Supported SBOM inputs:

- CycloneDX JSON/XML
- SPDX JSON/tag-value
- Syft JSON
- Grype vulnerability JSON
- Generic JSON/text with CVE IDs

Supported cloud and VEX inputs:

- Amazon Inspector and generic AWS/Azure finding JSON
- Microsoft Defender-style CSV/JSON
- OpenVEX
- CSAF VEX
- CycloneDX VEX

VEX is unverified input. Imported `Not affected`/`Fixed` claims do not authorize
suppression. Use the local Exposures decision form with rationale, evidence and
a review date for the exact CVE, component/version and file instance. Revoke
decisions from Data and operations; expired decisions cease suppressing. Same-named files
remain separate; a CVE-level summary cannot authorize suppression. Separate VEX
evidence must match a versioned package URL, package name plus version, or
immutable asset ID. Names alone, substrings, productless claims and conflicting
statuses never suppress an exposure.

Browser safety limits are 10 files per batch, 10 MiB per file, and 40 MiB total. Cloud and VEX evidence parsing runs only in a Web Worker with a 50,000-record batch budget, 10,000 source-row limit, 500-value dimension limit, 40-level nesting limit, and bounded cells/columns. Worker failure or timeout rejects evidence instead of reparsing it on the main thread. All SBOM JSON, text and XML parsing plus component/CVE aggregation run in a
worker. There is no main-thread fallback. The shared SBOM batch budget is 20,000
weighted parsing/expansion work units and 16 MiB normalized output, with 40-level
nesting, 200,000 structural nodes, 20,000 entries per collection and 8,192-character
fields. XML uses a bundled parser with DTD/entity declarations rejected and
bounded tags/entity expansion. A 15-second worker budget and 20-second main-thread
watchdog terminate failed processing while preserving existing imports. Dense
files can reach the work budget before the byte limit; split them and retry.

Run `npm run build:client` after editing frontend or worker code. `npm start`, verification,
release builds and Docker generate `public/generated/app.js` and `public/generated/sbom-worker.js`.
The browser uses these bundled entry points; bare package imports in source modules are not standalone web entry points.

## Local and Container Runs

```bash
npm ci --ignore-scripts
npm start
```

Open `http://127.0.0.1:5173`.

```bash
docker build -t vulnscope .
docker run --rm -p 127.0.0.1:5173:5173 --env-file .env -e HOST=0.0.0.0 vulnscope
```

The image runs as the non-root `node` user.

## Reverse Proxy

Keep the app on localhost or a private container network and terminate TLS at the proxy. When Nginx is the only network path to VulnScope:

```nginx
limit_req_zone $binary_remote_addr zone=vulnscope_api:10m rate=30r/m;

server {
  listen 443 ssl http2;
  server_name vulnscope.example.internal;

  ssl_certificate /etc/letsencrypt/live/vulnscope/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/vulnscope/privkey.pem;

  location /api/ {
    limit_req zone=vulnscope_api burst=10 nodelay;
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
  }

  location / {
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
  }
}
```

Set `TRUST_PROXY=1` only when the direct peer is loopback and that proxy overwrites (never appends) `X-Forwarded-For` from its trusted transport address. For multiple application instances, enforce shared rate limiting at the ingress, WAF, or another centralized control; in-memory limits are process-local.

## Known Boundary

Server-side case, SBOM, inventory, and browser-watchlist storage remain disabled until authentication and authorization exist. This prevents an unauthenticated shared data store from becoming an exposure or cross-user access problem.

Private repository scanning is also excluded. Adding it requires an authenticated
GitHub App or equivalent installation model, tenant-aware authorization,
repository allowlists, encrypted credential storage, revocation handling, and
an audit trail. Do not extend the current anonymous endpoint with a shared
private-repository token.

See [Public GitHub Repository Scanning](github-repository-scanning.md) for the
analyst workflow, supported inventory formats, interpretation guidance, and
failure recovery.
