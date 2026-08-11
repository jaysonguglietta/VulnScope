# VulnScope

VulnScope is a CVE research and exposure-triage console. Paste one CVE, research a batch, or load SBOM and cloud evidence to answer the questions that matter during remediation:

- Is exploitation confirmed, plausible, or only being discussed?
- Is exploit code public, and how credible is the evidence?
- Which packages and imported cloud assets are exposed?
- Do AWS or Azure advisories or customer-managed services intersect with the issue?
- What should an engineer validate, patch, mitigate, and monitor?

Production: [https://vulnscope.jsontechnology.com](https://vulnscope.jsontechnology.com)

## Product Workflows

### Deep CVE research

- Validates CVE IDs and collects NVD, CVE Services, CISA KEV, FIRST EPSS, GitHub Advisory Database, GitHub code and discussion leads, Hacker News, Reddit, and optional VulnCheck intelligence.
- Separates authoritative records, confirmed exploitation, public exploit leads, predictive risk, and public chatter.
- Produces a real-world verdict, risk score, evidence timeline, affected-product signals, cloud exposure analysis, and source health.
- Generates plain-text remediation, detection, cloud validation, ticket, executive, and risk-acceptance text with source links.
- Saves cases and watchlist entries locally in the browser and exports Markdown or JSON briefs.

### SBOM and package intelligence

- Loads up to 10 SBOMs per batch and parses them in a background browser worker.
- Supports CycloneDX JSON/XML, SPDX JSON/tag-value, Syft JSON, Grype JSON, and generic JSON/text containing CVEs.
- Shows the exact package rows associated with an SBOM CVE and automatically checks loaded SBOMs for the CVE currently being researched.
- Optionally enriches package URLs and ecosystems against OSV after explicit confirmation, including aliases, matching affected ranges, and package-specific fixed-version candidates with provenance.
- Preserves CycloneDX VEX analysis and applies VEX status to exposure prioritization.

### Exposure workspace

- Combines SBOM packages, OSV results, imported cloud findings, VEX statements, cases, watchlist entries, and bulk-research results.
- Filters by CVE, package or asset, source, severity, workflow status, and VEX status.
- Prioritizes confirmed exploitation, KEV membership, EPSS, CVSS, fix availability, and asset evidence while suppressing valid `not_affected` VEX statements.
- Exports the normalized exposure queue as CSV and opens any row directly in the full CVE investigation.

### Cloud and VEX evidence

- Imports Amazon Inspector findings and generic AWS/Azure vulnerability JSON.
- Imports Microsoft Defender-style CSV or JSON exports.
- Imports OpenVEX, CSAF VEX, and CycloneDX VEX statements.
- Lists affected assets, package or resource evidence, remediation details, and VEX justification without uploading the original files.

### Bulk research and scheduled monitoring

- Queues up to 25 CVEs for bounded, sequential bulk research and feeds completed results into the exposure workspace.
- Supports an optional AWS scheduled monitor configured at deployment time.
- The monitor stores 180-day snapshots in encrypted DynamoDB and sends SNS email only for material changes such as new KEV status, higher exploitation confidence, a meaningful EPSS jump, or new public code.

## Privacy Boundary

Raw SBOM, cloud finding, and VEX files are parsed locally and retained only in memory for the browser session. They are not uploaded to VulnScope, S3, Lambda, or a third party.

OSV enrichment is a separate, explicit action. After confirmation, VulnScope sends only normalized package identifiers, ecosystems, and versions to the server, which queries OSV. Do not enrich package metadata that your policy treats as confidential.

Case notes and watchlist entries are stored in browser local storage and pruned after 90 days. Authentication and request logging are intentionally excluded; do not treat this deployment as a shared confidential case-management system.

## Run Locally

Requires Node.js 20 or newer.

```bash
npm ci
npm start
```

Open `http://127.0.0.1:5173`. The server binds to localhost by default.

Optional source tokens improve coverage or rate limits:

```bash
NVD_API_KEY=... GITHUB_TOKEN=... VULNCHECK_API_TOKEN=... npm start
```

Use `.env.example` as a reference and do not commit real secrets.

## Verify

```bash
npm run verify
```

Verification includes server and browser-module syntax checks, API security smoke tests, SBOM/VEX/cloud/exposure parser tests, and a production-dependency audit.

## Security Defaults

- Security headers include CSP, HSTS in production, frame blocking, referrer policy, permissions policy, and content-sniffing protection.
- Research and enrichment requests have per-client rate limits, bounded queues, request-body limits, upstream response limits, and allowlisted API methods.
- AWS API Gateway throttles the stage to 2 requests per second with a burst of 5; API Lambda reserved concurrency is 2.
- Client identity uses the trusted API Gateway source address. Arbitrary forwarded headers are not trusted from public clients.
- Static and deployment-artifact buckets block public access and use server-side encryption; the static bucket also has versioning and lifecycle cleanup.
- External links are limited to HTTP(S), rendered text is escaped, and uploaded evidence is parsed as data rather than injected into markup.
- Source health reports observed success, failure, optional-token, or not-yet-checked state instead of implying every source is available.

The built-in controls reduce abuse; they do not replace authentication or authorization. Keep the public site free of sensitive case notes and inventory data until identity and tenant controls are added.

## AWS Deployment

The low-traffic architecture uses Route 53, CloudFront, a private S3 static origin, API Gateway HTTP API, and on-demand Lambda. Existing CloudWatch estimated-charge alarms email `Jayson.Guglietta@gmail.com` at `$10` and `$20`.

```bash
npm run deploy:aws
```

Enable scheduled CVE monitoring during deployment:

```bash
NOTIFICATION_EMAIL=Jayson.Guglietta@gmail.com \
MONITORED_CVES=CVE-2021-44228,CVE-2023-22527 \
npm run deploy:aws
```

AWS sends an SNS subscription-confirmation email the first time monitoring is enabled. Monitoring remains disabled when either the email or CVE list is empty.

See [docs/deployment.md](docs/deployment.md) for the resource inventory, route and quota details, validation commands, Docker and reverse-proxy guidance, and monitor operations. See [SECURITY.md](SECURITY.md) for the deployment boundary and reporting process.

## Limitations

VulnScope is a research and prioritization console, not an authenticated scanner or proof of exploitability. Search matches, public chatter, inferred cloud services, imported findings, and package-version ranges can be incomplete or wrong. Confirm decisions against vendor advisories, authoritative inventory, scanner evidence, compensating controls, and production telemetry.
