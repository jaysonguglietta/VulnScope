# VulnScope Deployment Notes

VulnScope is hardened for local use by default. It binds to `127.0.0.1`, keeps source tokens server-side, adds security headers, rate limits research requests, caps upstream responses, and stores case notes in browser local storage.

Authentication and request logging are intentionally not included yet.

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
