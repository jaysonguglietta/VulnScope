# VulnScope

VulnScope is a local web application for CVE research and vulnerability triage. Paste a CVE ID and it collects public intelligence from NVD, CVE Services, FIRST EPSS, CISA KEV, GitHub, Hacker News, Reddit, and optional VulnCheck API data.

It is designed to answer practical triage questions:

- Has this CVE been exploited?
- Are researchers, developers, or attackers talking about it?
- Is there public exploit code or exploit-related evidence?
- What should I patch or validate?
- Could AWS or Azure customer-managed services be affected?
- Do my uploaded SBOM files reference affected components or known CVEs?

## Run

```bash
npm ci
npm start
```

Open `http://127.0.0.1:5173`.

By default the server binds to `127.0.0.1`. To expose it intentionally, set `HOST=0.0.0.0` and put it behind TLS, access control, and network restrictions.

## Verify

```bash
npm run verify
```

This runs server syntax checks, client syntax checks, offline security smoke tests, and `npm audit --omit=dev`.

## Optional API Keys

The app works without keys, but these environment variables improve results or rate limits:

```bash
NVD_API_KEY=... GITHUB_TOKEN=... VULNCHECK_API_TOKEN=... npm start
```

Keys are read only by the local server. They are not written into the frontend bundle.

Use `.env.example` as a template and do not commit real `.env` files.

## Hardening Defaults

- Security headers are added to API and static responses, including CSP, frame blocking, referrer policy, and content sniffing protection.
- Research requests are rate limited per client address. Defaults: `RATE_LIMIT_MAX=30` requests per minute and `REFRESH_RATE_LIMIT_MAX=6` refreshes per minute.
- Research work is queued with bounded concurrency. Defaults: `RESEARCH_CONCURRENCY=4`, `RESEARCH_QUEUE_MAX=20`, `OUTBOUND_CONCURRENCY=8`, and `OUTBOUND_QUEUE_MAX=50`.
- Upstream JSON responses are capped at `RESPONSE_MAX_BYTES=8388608` bytes by default.
- The in-memory CVE cache is capped at `CACHE_MAX_ENTRIES=300` with a 10 minute TTL.
- Browser links from research sources are restricted to `http` and `https` URLs before rendering.
- Saved cases and watchlist entries are pruned after 90 days in this browser.
- SBOM files are parsed locally in the browser session and are not uploaded to the server.
- Markdown and JSON exports warn before download because they can contain analyst notes and case metadata.
- Evidence items include source reputation tiers so official records, predictive models, public code, exploit references, and chatter are separated.

Authentication and request logging are intentionally not included yet. Do not expose this app to untrusted users without adding an identity and authorization layer.

## Deployment

Production is currently deployed at [https://vulnscope.jsontechnology.com](https://vulnscope.jsontechnology.com).

The AWS deployment uses the lowest-maintenance serverless option for a low-traffic site:

- Route 53 hosts `jsontechnology.com` DNS.
- CloudFront serves TLS, security headers, and global edge delivery.
- S3 privately stores the static frontend.
- API Gateway HTTP API routes `/api/*` requests to Lambda.
- Lambda runs the VulnScope research API only when requests arrive.
- CloudWatch billing alarms send email alerts at estimated monthly charges of `$10` and `$20`.

Deploy updates with:

```bash
npm run deploy:aws
```

See [docs/deployment.md](docs/deployment.md) for the live AWS resource inventory, Docker/private-hosting notes, TLS reverse proxy guidance, secret handling, and multi-instance rate limiting guidance.

## What It Does

- Validates CVE IDs before research.
- Fetches official CVE metadata, CVSS, affected products, weaknesses, and references.
- Adds EPSS probability and CISA KEV exploitation status.
- Searches GitHub repository leads for public proof-of-concept indicators.
- Searches GitHub Issues/PRs, Hacker News, and Reddit for public chatter.
- Produces a real-world verdict that separates confirmed exploitation, public exploit leads, and community discussion.
- Estimates AWS and Azure exposure by separating official cloud advisory signals from possible customer-managed workload exposure.
- Uploads one or more SBOM files and extracts components, package URLs, CPEs, vulnerability rows, and CVE IDs.
- Supports CycloneDX JSON/XML, SPDX JSON/tag-value, Syft JSON, Grype vulnerability JSON, and generic CVE extraction from SBOM-like text.
- Lets analysts copy SBOM CVE lists, export SBOM summaries, and research any SBOM CVE directly in VulnScope.
- Compares loaded SBOM components against a researched CVE's affected product signals in the Impact tab.
- Builds a risk score, evidence list, remediation checklist, and timeline.
- Generates copy-ready remediation, detection, cloud impact, ticket, executive, and risk acceptance text.
- Saves case notes, owner, status, and tags in browser local storage.
- Watches CVEs for changes across risk, exploitation, evidence, chatter, cloud service candidates, and reference counts.
- Exports Markdown and JSON briefs.

## Limits

This is a research and triage console, not a scanner. GitHub matches, public chatter, exploit references, and cloud service candidates are leads, not proof of exploitability in your environment. Validate with asset inventory, cloud inventory, vendor advisories, scanner coverage, and telemetry before making remediation decisions.
