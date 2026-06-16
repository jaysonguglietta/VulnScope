import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";

let child;
const rootUrl = await startTestServer();

try {
  const index = request("/");
  assert(index.status === 200, `expected / to return 200, got ${index.status}`);
  assert(index.headers["content-security-policy"]?.includes("frame-ancestors 'none'"), "missing CSP frame protection");
  assert(index.headers["x-content-type-options"] === "nosniff", "missing nosniff header");
  assert(index.body.includes("VulnScope"), "index should include VulnScope brand");
  assert(index.body.includes("sbomInput"), "index should include SBOM upload input");

  const health = request("/api/health");
  assert(health.status === 200, `expected /api/health to return 200, got ${health.status}`);
  const healthJson = JSON.parse(health.body);
  assert(Array.isArray(healthJson.sources) && healthJson.sources.length >= 8, "health should return source catalog");
  assert(!Object.hasOwn(healthJson.sources[0], "configured"), "health should not expose token configuration state");

  const invalid = request("/api/research?cve=not-a-cve");
  assert(invalid.status === 400, `expected invalid CVE to return 400, got ${invalid.status}`);
  assert(JSON.parse(invalid.body).message.includes("CVE-YYYY-NNNN"), "invalid CVE should return a safe validation message");

  const traversal = request("/%2e%2e/%2e%2e/etc/passwd");
  assert(traversal.status !== 200, "path traversal probe must not return 200");
  assert(traversal.headers["content-security-policy"], "error responses should keep security headers");

  const first = request("/api/research?cve=CVE-2023-22527");
  const second = request("/api/research?cve=CVE-2023-22527");
  const third = request("/api/research?cve=CVE-2023-22527");
  assert(first.status === 200, `expected first research request to return 200, got ${first.status}`);
  assert(JSON.parse(first.body).id === "CVE-2023-22527", "research response should include requested CVE");
  assert(second.status === 200, `expected second research request to return 200, got ${second.status}`);
  assert(JSON.parse(second.body).cached === true, "second research response should come from cache");
  assert(third.status === 429, `expected third research request to return 429, got ${third.status}`);
  assert(third.headers["retry-after"], "rate limited response should include retry-after");

  console.log("security smoke tests passed");
} finally {
  stopTestServer();
}

async function startTestServer() {
  const port = await getFreePort();
  child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      MOCK_RESEARCH: "1",
      RATE_LIMIT_MAX: "2",
      REFRESH_RATE_LIMIT_MAX: "1",
      RATE_LIMIT_WINDOW_MS: "60000"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const deadline = Date.now() + 8000;
  while (!stdout.includes(`http://127.0.0.1:${port}`)) {
    if (child.exitCode !== null) {
      throw new Error(`test server exited early\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    if (Date.now() > deadline) {
      throw new Error(`test server did not start\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  return `http://127.0.0.1:${port}`;
}

async function getFreePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = address.port;
  server.close();
  await once(server, "close");
  return port;
}

function request(pathname) {
  const result = spawnSync("curl", ["-sS", "-D", "-", `${rootUrl}${pathname}`], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(`curl failed for ${pathname}: ${result.stderr || result.stdout}`);
  }
  return parseHttp(result.stdout);
}

function parseHttp(raw) {
  const parts = raw.split(/\r?\n\r?\n/).filter(Boolean);
  const headerBlock = parts.shift() || "";
  const body = parts.join("\n\n");
  const headerLines = headerBlock.split(/\r?\n/);
  const status = Number(headerLines[0]?.match(/\s(\d{3})\s/)?.[1] || 0);
  const headers = {};
  for (const line of headerLines.slice(1)) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    headers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
  }
  return { status, headers, body };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function stopTestServer() {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
}
