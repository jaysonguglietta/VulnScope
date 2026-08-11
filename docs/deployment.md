# VulnScope Deployment Notes

Production: `https://vulnscope.jsontechnology.com`

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

Raw SBOM, cloud, and VEX files remain in browser memory. The backend receives a CVE ID for research or, after explicit confirmation, a bounded set of normalized package identifiers for OSV enrichment.

## Resource Inventory

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

Estimated-charge alarms send to `Jayson.Guglietta@gmail.com`. Billing metrics and alarms are in `us-east-1`.

Scheduled-monitor resources are conditional. When enabled, the stack adds `vulnscope-monitor`, an EventBridge rule, an encrypted on-demand DynamoDB table, and a dedicated SNS topic/subscription. Read their generated identifiers from CloudFormation outputs and resources rather than assuming fixed ARNs.

## Deploy

From the repository root:

```bash
npm run verify
```

Run the GitHub `Release artifact` workflow for the desired commit. Download its `vulnscope-<commit>` artifact, verify the attestation, and deploy the extracted Lambda ZIP with its recorded checksum:

```bash
gh attestation verify ./release/lambda.zip \
  --repo jaysonguglietta/VulnScope \
  --signer-workflow jaysonguglietta/VulnScope/.github/workflows/release.yml \
  --deny-self-hosted-runners
LAMBDA_ARTIFACT_PATH=./release/lambda.zip \
LAMBDA_ARTIFACT_SHA256=$(shasum -a 256 ./release/lambda.zip | awk '{print $1}') \
npm run deploy:aws
```

The workflow pins every action by commit SHA, builds with `npm ci`, verifies npm registry signatures, generates an SPDX JSON SBOM, records a SHA-256 checksum, and creates GitHub-signed provenance for both the Lambda ZIP and SBOM. The Docker base is pinned to the immutable multi-platform digest corresponding to `node:22-alpine`.

Unsigned local builds are refused by default. `ALLOW_LOCAL_UNSIGNED_BUILD=1 npm run deploy:aws` is an explicit emergency break-glass path and should be documented in the change record when used.

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

1. Verifies the Lambda artifact checksum and GitHub build attestation, or packages a local build only through the explicit break-glass path.
2. Resolves the AWS account and public Route 53 hosted zone.
3. Deploys `infra/vulnscope-artifacts.yml`, which owns the private, encrypted, versioned artifact bucket and its lifecycle policy.
4. Uploads the immutable Lambda artifact and deploys `infra/vulnscope.yml`.
5. Syncs `public/` to the private static bucket and invalidates CloudFront.

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

Snapshots expire after 180 days. Update the CVE list by redeploying with the complete desired comma-separated list. Disable monitoring by deploying with empty `NOTIFICATION_EMAIL` and `MONITORED_CVES`; CloudFormation removes the conditional resources.

The browser watchlist is intentionally local and is not synchronized to the scheduled monitor because the application has no authenticated user account or server-side case store.

## API Contract and Limits

Production exposes only:

- `GET /api/health`
- `GET /api/research?cve=CVE-YYYY-NNNN[&refresh=1]`
- `POST /api/enrich`

CloudFront requires its full seven-method origin behavior whenever `POST` is enabled. The effective application allowlist is the three explicit API Gateway routes above; `PUT`, `PATCH`, `DELETE`, and unknown paths have no API Gateway route and do not invoke the Lambda.

The enrichment request is JSON and accepts no more than 50 package records. API bodies are capped at 256 KiB, hydrated OSV vulnerability details are capped at 40 per request, individual upstream responses are capped at 8 MiB, and the request has a 32 MiB aggregate response budget, 41-call budget, and 15-second outbound deadline. Warm Lambda environments cache up to 500 OSV detail records for one hour.

The CloudFront WAF blocks an IP after 100 requests in a five-minute evaluation window for `/api/` paths. API Gateway throttles the stage to 2 requests per second with a burst of 5. The API Lambda has reserved concurrency 2; the optional monitor has reserved concurrency 1. Application-level queues and rate limits provide an additional bound.

CloudFront adds `X-Origin-Verify` only on the API origin request. Lambda requires that value in AWS, preventing the documented API Gateway hostname from bypassing CloudFront and its WAF. Local and container deployments do not require the header unless `ORIGIN_VERIFY_SECRET` is configured.

Lambda uses API Gateway's `requestContext.http.sourceIp` as its trusted rate-limit identity. For a local reverse-proxy deployment, forwarded addresses are accepted only when `TRUST_PROXY=1` and the direct peer is loopback.

## Storage and Retention

- Static bucket: private OAC access, AES-256 encryption, versioning, noncurrent versions deleted after 7 days.
- Artifact bucket: retained CloudFormation resource with public access blocked, AES-256 encryption, ownership enforcement, versioning, incomplete-upload cleanup after 1 day, noncurrent-version cleanup after 7 days, and artifact expiration after 30 days by default.
- Browser uploads: memory only; cleared on refresh or by the user.
- Browser cases and watchlist: local storage; pruned after 90 days.
- Monitor snapshots: encrypted DynamoDB; TTL after 180 days.
- Lambda log groups: explicitly managed with 30-day retention and function-scoped write permissions.

## Production Validation

```bash
curl -I https://vulnscope.jsontechnology.com/
curl -sS https://vulnscope.jsontechnology.com/api/health
curl -sS 'https://vulnscope.jsontechnology.com/api/research?cve=CVE-2023-22527'
curl -i -X POST https://vulnscope.jsontechnology.com/api/research
```

Expected behavior:

- Static content returns CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer Policy, and Permissions Policy.
- Health reports source states truthfully as observed, optional, or not yet checked.
- Valid research returns JSON; invalid CVE IDs return `400`.
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

- S3 and CloudFront charge for small storage and request volume.
- HTTP API and Lambda charge per request/invocation.
- ACM public certificates have no separate certificate charge.
- Conditional DynamoDB, EventBridge, SNS, and monitor Lambda usage should remain small for a short CVE list and daily schedule.

The `$10` and `$20` alarms are account-level estimated-charge alarms, not hard spending limits. Unexpected traffic can accrue charges before an email is read. AWS WAF is intentionally omitted to preserve the low baseline cost; API Gateway throttling, Lambda concurrency, and application limits are the current abuse-cost controls.

## Source Tokens

The production stack works without optional tokens. These improve source coverage or rate limits:

- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `VULNCHECK_API_TOKEN`

Never commit them or add them to frontend files. For production, use Secrets Manager or another approved secret-injection path and tightly scoped IAM. The current template does not provision those secrets.

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

VEX is treated as unverified input. `Not affected` and `Fixed` claims apply only after the analyst approves them during import and only when the statement product exactly matches a package URL, package name, asset ID, or asset name. Ambiguous substring and productless matches never suppress an exposure.

Browser safety limits are 10 files per batch, 10 MiB per file, and 40 MiB total. Cloud and VEX evidence parsing runs only in a Web Worker with a 50,000-record batch budget, 10,000 source-row limit, 500-value dimension limit, 40-level nesting limit, and bounded cells/columns. Worker failure or timeout rejects evidence instead of reparsing it on the main thread. SBOM JSON and text parsing also use a worker; SBOM XML retains its browser DOM parser fallback.

## Local and Container Runs

```bash
npm ci
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
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }

  location / {
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
  }
}
```

Set `TRUST_PROXY=1` only when the direct peer is loopback and that proxy exclusively controls `X-Forwarded-For`. For multiple application instances, enforce shared rate limiting at the ingress, WAF, or another centralized control; in-memory limits are process-local.

## Known Boundary

Server-side case, SBOM, inventory, and browser-watchlist storage remain disabled until authentication and authorization exist. This prevents an unauthenticated shared data store from becoming an exposure or cross-user access problem.
