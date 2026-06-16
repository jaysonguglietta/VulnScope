# VulnScope Deployment Notes

VulnScope is hardened for local use by default. It binds to `127.0.0.1`, keeps source tokens server-side, adds security headers, rate limits research requests, caps upstream responses, and stores case notes in browser local storage.

Authentication and request logging are intentionally not included yet.

SBOM uploads are parsed locally in the browser session. The current SBOM workflow does not send uploaded files to the backend, S3, Lambda, or any third-party source. The app extracts components, package URLs, CPEs, embedded vulnerability rows, and CVE IDs client-side. The SBOM workspace lists all CVEs found in uploaded files, while a researched CVE automatically checks loaded SBOMs for an exact CVE match and surfaces affected package rows when available.

## Production AWS Deployment

Live site: `https://vulnscope.jsontechnology.com`

This deployment uses a cheap serverless architecture because the site is expected to receive only a few hits per day. Static files are served from S3 through CloudFront, and the research API runs on Lambda behind API Gateway only when a request arrives.

Request path:

```text
User browser
  -> Route 53 vulnscope.jsontechnology.com
  -> CloudFront distribution
  -> S3 private static bucket for /, /app.js, /styles.css
  -> API Gateway HTTP API for /api/*
  -> Lambda vulnscope-api
  -> Public CVE intelligence sources
```

Current AWS resource inventory:

- AWS account: `171058045575`
- Region: `us-east-1`
- CloudFormation stack: `vulnscope-prod`
- Hosted zone: `jsontechnology.com` / `ZE0UTGIT9KUYU`
- Domain: `vulnscope.jsontechnology.com`
- CloudFront distribution: `E19BTXYV3YQQSQ`
- CloudFront domain: `d306xsajqlo259.cloudfront.net`
- API Gateway endpoint: `https://0itdu9uhqc.execute-api.us-east-1.amazonaws.com`
- Lambda function: `vulnscope-api`
- Static bucket: `vulnscope-jsontechnology-com-171058045575`
- Artifact bucket: `vulnscope-artifacts-171058045575-us-east-1`
- ACM certificate: `arn:aws:acm:us-east-1:171058045575:certificate/41e49f5a-74e5-4901-ba91-f81a998a2183`
- Billing SNS topic: `arn:aws:sns:us-east-1:171058045575:vulnscope-cost-alerts`
- Billing alerts: `VulnScope-Monthly-EstimatedCharges-10USD` and `VulnScope-Monthly-EstimatedCharges-20USD`

Cost alert emails are configured for `Jayson.Guglietta@gmail.com`. AWS sends billing metrics from `us-east-1`, so the alarms are also in `us-east-1`.

## AWS Deploy Command

Deploy from the repository root:

```bash
npm run deploy:aws
```

The deploy script:

- Looks up the AWS account and Route 53 hosted zone.
- Creates or reuses the private deployment artifact bucket.
- Packages `server.mjs`, `lambda.mjs`, and `package.json` into a Lambda zip under `.deploy/`.
- Uploads the Lambda zip to S3.
- Deploys `infra/vulnscope.yml` with CloudFormation.
- Syncs `public/` to the private static S3 bucket.
- Creates a CloudFront invalidation.

The default deployment variables are:

```bash
AWS_REGION=us-east-1
STACK_NAME=vulnscope-prod
DOMAIN_NAME=vulnscope.jsontechnology.com
ROOT_DOMAIN=jsontechnology.com
```

Override them only when intentionally deploying another environment:

```bash
STACK_NAME=vulnscope-dev DOMAIN_NAME=vulnscope-dev.jsontechnology.com npm run deploy:aws
```

## AWS Validation

After deployment, validate the static site and API:

```bash
curl -I https://vulnscope.jsontechnology.com/
curl -sS https://vulnscope.jsontechnology.com/api/health
curl -sS "https://vulnscope.jsontechnology.com/api/research?cve=CVE-2023-22527"
```

The deployed site should return CloudFront security headers, including Content Security Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer Policy, Permissions Policy, and HSTS.

## Cheapest AWS Option Chosen

For a few hits per day, the chosen AWS path is normally cheaper and easier to operate than a continuously running EC2 instance, ECS service, or container host:

- S3 charges only for static storage and requests.
- CloudFront has very low cost for small traffic volumes.
- API Gateway HTTP API is less expensive than REST API for this use case.
- Lambda charges only when the API is invoked and avoids an always-on server.
- ACM public certificates are free for CloudFront.
- Route 53 hosted zone cost already exists for `jsontechnology.com`; the added record cost is negligible.

Expected baseline cost should stay low for light use, but billing alerts are configured at `$10` and `$20` so unexpected traffic or AWS resource drift is visible quickly.

## Cloud Source Tokens

The public deployment currently runs without optional source API tokens. VulnScope still researches CVEs through unauthenticated public sources, but optional tokens can improve rate limits and source coverage:

- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `VULNCHECK_API_TOKEN`

Do not commit these values. If the production deployment needs them, prefer AWS Secrets Manager or encrypted Lambda environment variables with tightly scoped IAM access. Avoid storing long-lived personal tokens directly in CloudFormation parameters.

## SBOM Upload Handling

Supported SBOM inputs:

- CycloneDX JSON and XML
- SPDX JSON and tag-value
- Syft JSON
- Grype vulnerability JSON
- Generic text or JSON files with embedded CVE IDs

Current limits are browser-side safety controls: up to 10 files per upload batch, 10 MB per file, and 40 MB total per batch. SBOM reports are kept only in memory for the current browser session and can be cleared from the sidebar. They are not persisted to local storage.

## Local Run

```bash
npm ci
npm start
```

Open `http://127.0.0.1:5173`.

## Environment Variables

Start from `.env.example` and keep real secrets out of Git:

```bash
cp .env.example .env
```

Important settings:

- `HOST`: defaults to `127.0.0.1`. Use `0.0.0.0` only behind trusted network controls.
- `NVD_API_KEY`, `GITHUB_TOKEN`, `VULNCHECK_API_TOKEN`: optional source tokens.
- `TRUST_PROXY=1`: use only when a trusted reverse proxy controls `X-Forwarded-For`.
- `RATE_LIMIT_MAX`, `REFRESH_RATE_LIMIT_MAX`: per-client abuse limits.
- `RESEARCH_CONCURRENCY`, `OUTBOUND_CONCURRENCY`: server-side work limits.
- `RESPONSE_MAX_BYTES`: max upstream JSON response size.

## Docker

Build:

```bash
docker build -t vulnscope .
```

Run local-only:

```bash
docker run --rm -p 127.0.0.1:5173:5173 --env-file .env -e HOST=0.0.0.0 vulnscope
```

The image runs as the non-root `node` user and does not require write access to the application directory.

## TLS Reverse Proxy

For a single-user private deployment, terminate HTTPS at a reverse proxy and keep VulnScope bound to localhost or a private container network.

Nginx example:

```nginx
limit_req_zone $binary_remote_addr zone=vulnscope_api:10m rate=30r/m;

server {
  listen 443 ssl http2;
  server_name vulnscope.example.internal;

  ssl_certificate /etc/letsencrypt/live/vulnscope/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/vulnscope/privkey.pem;

  location /api/research {
    limit_req zone=vulnscope_api burst=10 nodelay;
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }

  location / {
    proxy_pass http://127.0.0.1:5173;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

Set `TRUST_PROXY=1` only when the proxy is the only path to the app.

## Distributed Rate Limiting

The built-in rate limiter is in-memory and protects a single VulnScope process. For multiple app instances, use a shared enforcement point:

- Nginx `limit_req_zone` at the reverse proxy.
- Cloudflare/WAF rate limiting in front of the app.
- Kubernetes ingress rate limiting.
- A future Redis-backed limiter if the app needs native multi-instance enforcement.

Do not rely on per-process limits alone when running more than one instance.

## Server-Side Case Storage

Server-side case storage is intentionally not enabled without authentication. Browser-local case storage avoids creating a shared unauthenticated case database. If this becomes a team tool, add identity first, then store cases server-side with per-user or per-team authorization and retention controls.
