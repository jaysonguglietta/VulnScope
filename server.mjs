import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const publicDir = resolve(__dirname, "public");
const port = Number(process.env.PORT || 5173);
const host = process.env.HOST || "127.0.0.1";
const cache = new Map();
const cacheTtlMs = 10 * 60 * 1000;
const requestTimeoutMs = 10000;
const cacheMaxEntries = positiveInt(process.env.CACHE_MAX_ENTRIES, 300);
const responseMaxBytes = positiveInt(process.env.RESPONSE_MAX_BYTES, 8 * 1024 * 1024);
const rateLimitWindowMs = positiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60 * 1000);
const rateLimitMaxRequests = positiveInt(process.env.RATE_LIMIT_MAX, 30);
const refreshRateLimitMaxRequests = positiveInt(process.env.REFRESH_RATE_LIMIT_MAX, 6);
const researchConcurrency = positiveInt(process.env.RESEARCH_CONCURRENCY, 4);
const researchQueueMax = positiveInt(process.env.RESEARCH_QUEUE_MAX, 20);
const outboundConcurrency = positiveInt(process.env.OUTBOUND_CONCURRENCY, 8);
const outboundQueueMax = positiveInt(process.env.OUTBOUND_QUEUE_MAX, 50);
const apiBodyMaxBytes = positiveInt(process.env.API_BODY_MAX_BYTES, 256 * 1024);
const enrichmentPackageMax = positiveInt(process.env.ENRICHMENT_PACKAGE_MAX, 200);
const enrichmentVulnerabilityMax = positiveInt(process.env.ENRICHMENT_VULNERABILITY_MAX, 120);
const rateLimitBuckets = new Map();
const researchQueue = [];
const outboundQueue = [];
const sourceTelemetry = new Map();
let activeResearch = 0;
let activeOutbound = 0;

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon"
};

const securityHeaders = {
  "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff"
};

const sourceCatalog = [
  {
    id: "nvd",
    label: "NVD CVE API",
    kind: "official",
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  },
  {
    id: "cve",
    label: "CVE Services",
    kind: "official",
    url: "https://cveawg.mitre.org/api/cve"
  },
  {
    id: "epss",
    label: "FIRST EPSS",
    kind: "official",
    url: "https://api.first.org/data/v1/epss"
  },
  {
    id: "kev",
    label: "CISA KEV Catalog",
    kind: "official",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  },
  {
    id: "github",
    label: "GitHub Repositories",
    kind: "public-search",
    url: "https://api.github.com/search/repositories"
  },
  {
    id: "githubIssues",
    label: "GitHub Issues and PRs",
    kind: "public-search",
    url: "https://api.github.com/search/issues"
  },
  {
    id: "githubAdvisories",
    label: "GitHub Advisory Database",
    kind: "official",
    url: "https://api.github.com/advisories"
  },
  {
    id: "hackerNews",
    label: "Hacker News Chatter",
    kind: "public-search",
    url: "https://hn.algolia.com/api/v1/search"
  },
  {
    id: "reddit",
    label: "Reddit Chatter",
    kind: "public-search",
    url: "https://www.reddit.com/search.json"
  },
  {
    id: "vulncheck",
    label: "VulnCheck Exploit Intel",
    kind: "optional-token",
    url: "https://api.vulncheck.com/v3/index/exploits"
  },
  {
    id: "osv",
    label: "OSV Package Intelligence",
    kind: "package-intelligence",
    url: "https://api.osv.dev/v1/querybatch"
  }
];

const cloudServiceCatalog = [
  {
    provider: "AWS",
    service: "Amazon Linux / EC2 AMIs",
    keywords: ["amazon linux", "linux kernel", "glibc", "openssl", "openssh", "sudo", "curl", "runc", "containerd", "docker", "apache", "nginx"],
    action: "Check EC2 instances, launch templates, golden AMIs, and package baselines for affected software and patched Amazon Linux advisories.",
    url: "https://alas.aws.amazon.com/"
  },
  {
    provider: "AWS",
    service: "Amazon EC2 customer-managed workloads",
    keywords: ["server", "data center", "datacenter", "self-hosted", "apache", "nginx", "tomcat", "confluence", "jira", "wordpress", "jenkins", "gitlab", "openssl", "openssh"],
    action: "Search EC2 inventory, scanner output, AMIs, and internet-facing instances for the affected product or package.",
    url: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html"
  },
  {
    provider: "AWS",
    service: "Amazon ECS",
    keywords: ["container", "containers", "docker", "runc", "containerd", "java", "log4j", "spring", "tomcat", "nginx"],
    action: "Check ECS task images, ECS-optimized AMIs, container runtime versions, and service deployments.",
    url: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html"
  },
  {
    provider: "AWS",
    service: "Amazon EKS",
    keywords: ["kubernetes", "kubelet", "container", "containers", "docker", "runc", "containerd", "cni", "ingress", "istio", "envoy"],
    action: "Check EKS node groups, optimized AMIs, add-ons, controller images, and running pods for affected components.",
    url: "https://docs.aws.amazon.com/eks/latest/userguide/security.html"
  },
  {
    provider: "AWS",
    service: "AWS Fargate",
    keywords: ["fargate", "container", "containers", "docker", "runc", "containerd"],
    action: "Review whether the CVE affects your container images or a managed Fargate platform version called out by AWS.",
    url: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html"
  },
  {
    provider: "AWS",
    service: "AWS Lambda",
    keywords: ["lambda", "java", "node.js", "nodejs", "python", "ruby", ".net", "runtime", "openssl", "glibc", "log4j"],
    action: "Check Lambda runtimes, layers, deployment packages, and container images for vulnerable libraries or runtime packages.",
    url: "https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html"
  },
  {
    provider: "AWS",
    service: "AWS Elastic Beanstalk",
    keywords: ["elastic beanstalk", "java", "tomcat", "php", "node.js", "python", "ruby", "docker", "nginx", "apache", "log4j"],
    action: "Check platform versions and application dependencies; update managed platform branches or custom images as needed.",
    url: "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.platform.upgrade.html"
  },
  {
    provider: "AWS",
    service: "Amazon RDS / Aurora",
    keywords: ["postgresql", "mysql", "mariadb", "oracle", "sql server", "database", "jdbc", "openssl"],
    action: "Check engine family, minor versions, extensions, client drivers, and AWS advisories before scheduling database maintenance.",
    url: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html"
  },
  {
    provider: "AWS",
    service: "Amazon OpenSearch Service",
    keywords: ["opensearch", "elasticsearch", "lucene", "log4j"],
    action: "Check domain engine versions, plugins, and any self-managed OpenSearch or Elasticsearch clusters.",
    url: "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/security.html"
  },
  {
    provider: "AWS",
    service: "Amazon MSK",
    keywords: ["kafka", "zookeeper", "log4j"],
    action: "Check MSK broker versions, Kafka clients, connectors, and any self-managed Kafka clusters.",
    url: "https://docs.aws.amazon.com/msk/latest/developerguide/security.html"
  },
  {
    provider: "AWS",
    service: "Amazon EMR / AWS Glue / SageMaker notebooks",
    keywords: ["spark", "hadoop", "hive", "jupyter", "notebook", "python", "container", "docker", "log4j"],
    action: "Check cluster releases, job images, notebooks, libraries, and long-running endpoints for vulnerable packages.",
    url: "https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security.html"
  },
  {
    provider: "Azure",
    service: "Azure Virtual Machines / Azure images",
    keywords: ["windows", "linux kernel", "azure linux", "cbl-mariner", "openssl", "openssh", "sudo", "apache", "nginx", "tomcat", "confluence", "jira", "jenkins", "gitlab"],
    action: "Search Azure VM inventory, images, extensions, and scanner output for affected packages or third-party software.",
    url: "https://learn.microsoft.com/azure/virtual-machines/security-policy"
  },
  {
    provider: "Azure",
    service: "Azure Kubernetes Service (AKS)",
    keywords: ["kubernetes", "kubelet", "container", "containers", "docker", "runc", "containerd", "cni", "ingress", "istio", "envoy"],
    action: "Check AKS node images, add-ons, controllers, container images, and running workloads for affected components.",
    url: "https://learn.microsoft.com/azure/aks/concepts-security"
  },
  {
    provider: "Azure",
    service: "Azure Container Apps / Azure Container Instances",
    keywords: ["container apps", "container instances", "container", "containers", "docker", "runc", "containerd", "java", "log4j", "nginx"],
    action: "Check container images, base images, managed environment settings, and Azure advisories for platform-level exposure.",
    url: "https://learn.microsoft.com/azure/container-apps/security"
  },
  {
    provider: "Azure",
    service: "Azure App Service",
    keywords: ["app service", "java", "tomcat", "node.js", "nodejs", "python", "php", ".net", "docker", "nginx", "apache", "log4j"],
    action: "Check runtime stacks, site extensions, container images, application dependencies, and platform update guidance.",
    url: "https://learn.microsoft.com/azure/app-service/overview-security"
  },
  {
    provider: "Azure",
    service: "Azure Functions",
    keywords: ["functions", "java", "node.js", "nodejs", "python", ".net", "runtime", "openssl", "glibc", "log4j"],
    action: "Check function runtimes, extensions, deployment packages, and custom container images.",
    url: "https://learn.microsoft.com/azure/azure-functions/security-concepts"
  },
  {
    provider: "Azure",
    service: "Azure Spring Apps",
    keywords: ["spring", "spring boot", "java", "tomcat", "log4j"],
    action: "Check Spring applications, Java dependencies, build artifacts, and managed platform guidance.",
    url: "https://learn.microsoft.com/azure/spring-apps/enterprise/security-controls"
  },
  {
    provider: "Azure",
    service: "Azure SQL / Azure Database services",
    keywords: ["sql server", "postgresql", "mysql", "mariadb", "database", "jdbc", "odbc", "openssl"],
    action: "Check database engine versions, maintenance channels, extensions, and client drivers.",
    url: "https://learn.microsoft.com/azure/azure-sql/database/security-overview"
  },
  {
    provider: "Azure",
    service: "Azure Databricks / Synapse / HDInsight",
    keywords: ["spark", "hadoop", "hive", "databricks", "synapse", "notebook", "jupyter", "log4j", "python"],
    action: "Check cluster runtimes, libraries, job images, notebooks, and long-running workspaces.",
    url: "https://learn.microsoft.com/azure/databricks/security/"
  },
  {
    provider: "Azure",
    service: "Microsoft Defender for Cloud / Microsoft security agents",
    keywords: ["defender", "antimalware", "malware protection engine", "security agent", "azure monitor agent", "log analytics agent"],
    action: "Check Microsoft security advisory status, agent versions, automatic updates, and Defender for Cloud recommendations.",
    url: "https://msrc.microsoft.com/update-guide"
  }
];

function positiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function isPathInside(parent, child) {
  const delta = relative(parent, child);
  return delta === "" || (!delta.startsWith("..") && !isAbsolute(delta));
}

function withSecurityHeaders(headers = {}) {
  return {
    ...securityHeaders,
    ...headers
  };
}

function getCachedResearch(cve) {
  const cached = cache.get(cve);
  if (!cached) return null;
  if (Date.now() - cached.createdAt >= cacheTtlMs) {
    cache.delete(cve);
    return null;
  }
  cache.delete(cve);
  cache.set(cve, cached);
  return cached;
}

function setCachedResearch(cve, payload) {
  cache.set(cve, { createdAt: Date.now(), payload });
  while (cache.size > cacheMaxEntries) {
    const oldestKey = cache.keys().next().value;
    if (!oldestKey) break;
    cache.delete(oldestKey);
  }
}

function getClientKey(req) {
  if (req.trustedClientAddress) return req.trustedClientAddress;
  const remoteAddress = req.socket?.remoteAddress || "unknown";
  if (process.env.TRUST_PROXY === "1" && isLoopbackAddress(remoteAddress)) {
    const forwardedFor = req.headers["x-forwarded-for"];
    const forwardedValue = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    const firstForwarded = forwardedValue?.split(",")[0]?.trim();
    if (firstForwarded) return firstForwarded;
  }
  return remoteAddress;
}

function isLoopbackAddress(value) {
  const address = String(value || "").toLowerCase();
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function checkResearchRateLimit(req, refresh) {
  const now = Date.now();
  const key = getClientKey(req);
  const existing = rateLimitBuckets.get(key);
  const bucket =
    existing && now - existing.windowStart < rateLimitWindowMs
      ? existing
      : { windowStart: now, count: 0, refreshCount: 0 };

  bucket.count += 1;
  if (refresh) bucket.refreshCount += 1;
  rateLimitBuckets.set(key, bucket);
  pruneRateLimitBuckets(now);

  const retryAfterSeconds = Math.max(1, Math.ceil((rateLimitWindowMs - (now - bucket.windowStart)) / 1000));
  if (bucket.count > rateLimitMaxRequests) {
    return {
      allowed: false,
      retryAfterSeconds,
      message: "Too many research requests. Wait a moment and try again."
    };
  }
  if (refresh && bucket.refreshCount > refreshRateLimitMaxRequests) {
    return {
      allowed: false,
      retryAfterSeconds,
      message: "Too many refresh requests. Wait a moment and try again."
    };
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

function pruneRateLimitBuckets(now) {
  if (rateLimitBuckets.size < 1000) return;
  for (const [key, bucket] of rateLimitBuckets.entries()) {
    if (now - bucket.windowStart >= rateLimitWindowMs) rateLimitBuckets.delete(key);
  }
}

function canAcceptResearch() {
  return activeResearch < researchConcurrency || researchQueue.length < researchQueueMax;
}

async function withResearchSlot(fn) {
  if (activeResearch >= researchConcurrency) {
    if (researchQueue.length >= researchQueueMax) {
      throw new Error("Research queue is busy.");
    }
    await new Promise((resolveQueue) => researchQueue.push(resolveQueue));
  }

  activeResearch += 1;
  try {
    return await fn();
  } finally {
    activeResearch -= 1;
    const next = researchQueue.shift();
    if (next) next();
  }
}

async function withOutboundSlot(fn) {
  if (activeOutbound >= outboundConcurrency) {
    if (outboundQueue.length >= outboundQueueMax) {
      throw new Error("Outbound source queue is busy. Try again shortly.");
    }
    await new Promise((resolveQueue) => outboundQueue.push(resolveQueue));
  }

  activeOutbound += 1;
  try {
    return await fn();
  } finally {
    activeOutbound -= 1;
    const next = outboundQueue.shift();
    if (next) next();
  }
}

async function readLimitedResponseText(response) {
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength > responseMaxBytes) {
    throw new Error(`Source response exceeded ${formatBytes(responseMaxBytes)}.`);
  }

  if (!response.body) {
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > responseMaxBytes) {
      throw new Error(`Source response exceeded ${formatBytes(responseMaxBytes)}.`);
    }
    return text;
  }

  const chunks = [];
  let received = 0;
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > responseMaxBytes) {
      await reader.cancel();
      throw new Error(`Source response exceeded ${formatBytes(responseMaxBytes)}.`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, received).toString("utf8");
}

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${Math.round(bytes / (1024 * 1024))} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}

function clientSafeError(error) {
  const message = String(error?.message || "");
  if (
    message === "Request timed out." ||
    message === "Source returned invalid JSON." ||
    message.startsWith("Source returned ") ||
    message.startsWith("Source response exceeded ") ||
    message.startsWith("Outbound source queue is busy") ||
    /^No .+ returned/.test(message)
  ) {
    return message;
  }
  return "Source failed.";
}

export async function appRequestHandler(req, res) {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const method = String(req.method || "GET").toUpperCase();
    const body = url.pathname.startsWith("/api/") && !["GET", "HEAD"].includes(method)
      ? await readLimitedRequestBody(req)
      : "";
    const apiResponse = await handleApiRequest({
      path: url.pathname,
      method,
      query: url.searchParams,
      headers: req.headers,
      remoteAddress: req.socket?.remoteAddress,
      body
    });
    if (apiResponse) {
      writeApiResponse(res, apiResponse);
      return;
    }

    await serveStatic(url.pathname, res);
  } catch (error) {
    console.error(error);
    const status = Number(error?.statusCode) || 500;
    const body = status === 500
      ? genericServerErrorBody()
      : { error: true, message: error?.clientMessage || "Request rejected." };
    sendJson(res, body, status);
  }
}

export async function handleApiRequest({
  path,
  method = "GET",
  query = new URLSearchParams(),
  headers = {},
  remoteAddress = "unknown",
  trustedClientAddress = "",
  body = ""
}) {
  const normalizedMethod = String(method || "GET").toUpperCase();
  if (path === "/api/health") {
    if (normalizedMethod !== "GET") return methodNotAllowed(["GET"]);
    return jsonApiResponse({
      ok: true,
      generatedAt: new Date().toISOString(),
      sources: sourceCatalog.map((source) => ({
        ...sourceTelemetry.get(source.id),
        id: source.id,
        label: source.label,
        kind: source.kind,
        url: source.url,
        optional: source.kind === "optional-token",
        status: sourceTelemetry.get(source.id)?.status || (source.kind === "optional-token" ? "optional" : "unknown"),
        message: sourceTelemetry.get(source.id)?.message || (source.kind === "optional-token" ? "Optional source has not been queried." : "No live source check has run in this process.")
      }))
    });
  }

  if (path === "/api/research") {
    if (normalizedMethod !== "GET") return methodNotAllowed(["GET"]);
    const cve = normalizeCve(query.get("cve"));
    const refresh = query.get("refresh") === "1";
    if (!cve) {
      return jsonApiResponse(
        {
          error: true,
          message: "Enter a CVE in the format CVE-YYYY-NNNN."
        },
        400
      );
    }

    const rateLimit = checkResearchRateLimit({ headers, socket: { remoteAddress }, trustedClientAddress }, refresh);
    if (!rateLimit.allowed) {
      return jsonApiResponse(
        {
          error: true,
          message: rateLimit.message
        },
        429,
        { "retry-after": String(rateLimit.retryAfterSeconds) }
      );
    }

    const cached = getCachedResearch(cve);
    if (!refresh && cached) {
      return jsonApiResponse({ ...cached.payload, cached: true });
    }

    if (!canAcceptResearch()) {
      return jsonApiResponse(
        {
          error: true,
          message: "The research queue is busy. Try again shortly."
        },
        503,
        { "retry-after": "10" }
      );
    }

    const payload = await withResearchSlot(() => researchCve(cve));
    setCachedResearch(cve, payload);
    return jsonApiResponse(payload);
  }

  if (path === "/api/enrich") {
    if (normalizedMethod !== "POST") return methodNotAllowed(["POST"]);
    if (Buffer.byteLength(String(body || ""), "utf8") > apiBodyMaxBytes) {
      return jsonApiResponse({ error: true, message: "Enrichment request is too large." }, 413);
    }
    const request = parseJsonBody(body);
    if (!request.ok) return jsonApiResponse({ error: true, message: request.message }, 400);
    const packages = normalizeEnrichmentPackages(request.value?.packages);
    if (!packages.length) {
      return jsonApiResponse({ error: true, message: "Provide at least one package with a package URL or an ecosystem, name, and version." }, 400);
    }
    const rateLimit = checkResearchRateLimit({ headers, socket: { remoteAddress }, trustedClientAddress }, false);
    if (!rateLimit.allowed) {
      return jsonApiResponse({ error: true, message: rateLimit.message }, 429, { "retry-after": String(rateLimit.retryAfterSeconds) });
    }
    if (!canAcceptResearch()) {
      return jsonApiResponse({ error: true, message: "The research queue is busy. Try again shortly." }, 503, { "retry-after": "10" });
    }
    const payload = await withResearchSlot(() => enrichPackages(packages));
    return jsonApiResponse(payload);
  }

  if (path.startsWith("/api/")) {
    return jsonApiResponse({ error: true, message: "API route not found." }, 404);
  }
  return null;
}

function methodNotAllowed(allowed) {
  return jsonApiResponse(
    { error: true, message: `Method not allowed. Use ${allowed.join(" or ")}.` },
    405,
    { allow: allowed.join(", ") }
  );
}

async function readLimitedRequestBody(req) {
  const declaredLength = Number(req.headers["content-length"] || 0);
  if (declaredLength > apiBodyMaxBytes) {
    const error = new Error("Request body too large.");
    error.statusCode = 413;
    error.clientMessage = "Request body is too large.";
    throw error;
  }
  const chunks = [];
  let received = 0;
  for await (const chunk of req) {
    received += chunk.length;
    if (received > apiBodyMaxBytes) {
      const error = new Error("Request body too large.");
      error.statusCode = 413;
      error.clientMessage = "Request body is too large.";
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, received).toString("utf8");
}

function parseJsonBody(body) {
  try {
    return { ok: true, value: JSON.parse(String(body || "{}")) };
  } catch {
    return { ok: false, message: "Request body must be valid JSON." };
  }
}

const server = createServer(appRequestHandler);

if (isMainModule()) {
  server.listen(port, host, () => {
    console.log(`VulnScope is running at http://${host}:${port}`);
    if (host === "0.0.0.0" || host === "::") {
      console.warn("The server is listening on all interfaces. Put it behind TLS, access control, and rate limiting before exposing it.");
    }
  });
}

function isMainModule() {
  return process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
}

async function serveStatic(pathname, res) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  let decoded;
  try {
    decoded = decodeURIComponent(requested);
  } catch {
    sendText(res, "Bad request", 400);
    return;
  }
  const normalizedPath = normalize(decoded).replace(/^(\.\.[/\\])+/, "");
  const safePath = normalizedPath.startsWith("/") ? `.${normalizedPath}` : normalizedPath;
  const filePath = resolve(publicDir, safePath);

  if (!isPathInside(publicDir, filePath)) {
    sendText(res, "Forbidden", 403);
    return;
  }

  try {
    const fileStat = await stat(filePath);
    const finalPath = fileStat.isDirectory() ? join(filePath, "index.html") : filePath;
    const body = await readFile(finalPath);
    const type = mimeTypes[extname(finalPath)] || "application/octet-stream";
    res.writeHead(200, withSecurityHeaders({
      "content-type": type,
      "cache-control": "no-store"
    }));
    res.end(body);
  } catch {
    sendText(res, "Not found", 404);
  }
}

export async function researchCve(cve) {
  const generatedAt = new Date().toISOString();
  if (process.env.MOCK_RESEARCH === "1") {
    return buildMockResearch(cve, generatedAt);
  }
  const tasks = [
    sourceTask("nvd", () => fetchNvd(cve)),
    sourceTask("cve", () => fetchCveOrg(cve)),
    sourceTask("epss", () => fetchEpss(cve)),
    sourceTask("kev", () => fetchKev(cve)),
    sourceTask("github", () => fetchGitHubRepos(cve)),
    sourceTask("githubIssues", () => fetchGitHubIssues(cve)),
    sourceTask("githubAdvisories", () => fetchGitHubAdvisories(cve)),
    sourceTask("hackerNews", () => fetchHackerNews(cve)),
    sourceTask("reddit", () => fetchReddit(cve)),
    sourceTask("vulncheck", () => fetchVulnCheck(cve))
  ];

  const settled = await Promise.all(tasks);
  const sources = Object.fromEntries(settled.map((result) => [result.id, result]));
  const nvd = sources.nvd.data || null;
  const cveOrg = sources.cve.data || null;
  const epss = sources.epss.data || null;
  const kev = sources.kev.data || null;
  const github = sources.github.data || null;
  const githubIssues = sources.githubIssues.data || null;
  const githubAdvisories = sources.githubAdvisories.data || null;
  const hackerNews = sources.hackerNews.data || null;
  const reddit = sources.reddit.data || null;
  const vulncheck = sources.vulncheck.data || null;

  const title = pickTitle(cve, nvd, cveOrg, kev);
  const description = pickDescription(nvd, cveOrg, kev);
  const cvss = extractCvss(nvd, cveOrg);
  const affected = extractAffectedProducts(nvd, cveOrg, kev);
  const weaknesses = extractWeaknesses(nvd, cveOrg, kev);
  const references = dedupeByUrl([
    ...extractNvdReferences(nvd),
    ...extractCveOrgReferences(cveOrg),
    ...extractKevReferences(kev),
    ...extractGitHubAdvisoryReferences(githubAdvisories)
  ]);
  const evidence = enrichEvidenceConfidence(buildEvidence(cve, { nvd, cveOrg, epss, kev, github, githubIssues, githubAdvisories, hackerNews, reddit, vulncheck, references }));
  const timeline = buildTimeline({ nvd, cveOrg, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, references });
  const remediation = buildRemediation(cve, { kev, references, affected, title, cvss });
  const realWorld = buildRealWorldAssessment(cve, { cvss, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, references, evidence });
  const risk = calculateRisk({ cvss, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, evidence });
  const exploitMaturity = buildExploitMaturity(cve, { kev, github, references, vulncheck, evidence, epss });
  const evidenceConfidence = buildEvidenceConfidenceSummary(evidence);
  const vendorPatch = buildVendorPatchIntelligence(cve, { affected, references, remediation });
  const cloudImpact = buildCloudImpact(cve, { title, description, affected, references, kev });
  const detectionGuidance = buildDetectionGuidance(cve, { title, cvss, kev, weaknesses, realWorld, exploitMaturity, references });
  const executiveBrief = buildExecutiveBrief(cve, { title, risk, realWorld, exploitMaturity, vendorPatch, cloudImpact, remediation, affected });
  const ticketExport = buildTicketExport(cve, { title, risk, realWorld, exploitMaturity, vendorPatch, cloudImpact, remediation, affected, detectionGuidance });
  const riskAcceptance = buildRiskAcceptanceNote(cve, { title, risk, realWorld, exploitMaturity, remediation, detectionGuidance });
  const sourceResults = settled.map(({ data, ...source }) => source);

  return {
    id: cve,
    generatedAt,
    cached: false,
    title,
    description,
    status: nvd?.vulnStatus || cveOrg?.state || "Unknown",
    risk,
    confidence: calculateConfidence(sourceResults, nvd, cveOrg),
    executiveSummary: buildExecutiveSummary(cve, title, description, {
      cvss,
      epss,
      kev,
      github,
      githubIssues,
      hackerNews,
      reddit,
      vulncheck,
      affected,
      risk,
      realWorld,
      cloudImpact
    }),
    metrics: {
      cvss,
      epss,
      kev: kev ? summarizeKev(kev) : null,
      github: github ? summarizeGithub(github) : null,
      githubIssues: githubIssues ? summarizeGithubIssues(githubIssues) : null,
      githubAdvisories: githubAdvisories ? summarizeGithubAdvisories(githubAdvisories) : null,
      hackerNews: hackerNews ? summarizeHackerNews(hackerNews) : null,
      reddit: reddit ? summarizeReddit(reddit) : null,
      realWorld,
      references: references.length,
      affectedProducts: affected.length,
      weaknesses: weaknesses.length,
      exploitMaturity,
      evidenceConfidence,
      cloudImpact
    },
    affected,
    weaknesses,
    references,
    evidence,
    timeline,
    remediation,
    realWorld,
    exploitMaturity,
    evidenceConfidence,
    vendorPatch,
    cloudImpact,
    detectionGuidance,
    executiveBrief,
    ticketExport,
    riskAcceptance,
    sourceResults,
    sourceLinks: buildSourceLinks(cve),
    analystActions: buildAnalystActions({ cve, risk, realWorld, kev, epss, github, githubIssues, hackerNews, reddit, vulncheck, affected, references, cloudImpact })
  };
}

function buildMockResearch(cve, generatedAt) {
  const sourceResults = sourceCatalog.map((source) => ({
    id: source.id,
    label: source.label,
    status: source.kind === "optional-token" ? "skipped" : "ok",
    message: source.kind === "optional-token" ? "Optional source unavailable in mock mode." : "Loaded mock source.",
    latencyMs: 0,
    url: source.url
  }));
  const evidence = enrichEvidenceConfidence([
    {
      id: "mock-nvd",
      type: "primary-record",
      source: "NVD",
      title: "Mock NVD record",
      url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      description: "Offline test record used for security smoke tests.",
      date: generatedAt,
      confidence: "high",
      tags: ["official", "mock"]
    },
    {
      id: "mock-epss",
      type: "probability",
      source: "FIRST EPSS",
      title: "Mock EPSS probability",
      url: `https://api.first.org/data/v1/epss?cve=${cve}`,
      description: "Offline probability signal used for smoke tests.",
      date: generatedAt,
      confidence: "medium",
      tags: ["model", "mock"]
    }
  ]);
  const evidenceConfidence = buildEvidenceConfidenceSummary(evidence);
  const realWorld = {
    verdict: "Needs validation",
    score: 35,
    confidence: "Medium",
    exploitedStatus: "No confirmed exploitation in mock data",
    chatterLevel: "None",
    publicExploitLevel: "None",
    summary: "Mock research mode is enabled. Use live mode for real CVE intelligence.",
    counts: {
      exploitReferences: 0,
      publicCode: 0,
      githubDiscussions: 0,
      hackerNews: 0,
      reddit: 0,
      totalChatter: 0,
      engagedChatter: 0
    },
    signals: []
  };
  const cloudImpact = {
    summary: "Mock mode did not infer AWS or Azure impact.",
    providers: [],
    services: [],
    links: buildCloudImpactLinks(cve),
    officialRefs: [],
    plainText: `Cloud impact review for ${cve}\nMock mode did not infer AWS or Azure impact.`
  };
  return {
    id: cve,
    generatedAt,
    cached: false,
    title: `${cve} mock research record`,
    description: "This offline payload is generated only when MOCK_RESEARCH=1 is set.",
    status: "Mock",
    risk: { score: 35, level: "Medium", reasons: ["mock source data"] },
    confidence: { score: 70, label: "Medium" },
    executiveSummary: `${cve} mock research record. Live external research was bypassed for security smoke testing.`,
    metrics: {
      cvss: { source: "mock", version: "3.1", score: 5.0, severity: "MEDIUM", vector: "MOCK" },
      epss: { cve, epss: 0.1, percentile: 0.5, date: generatedAt.slice(0, 10) },
      kev: null,
      github: null,
      githubIssues: null,
      hackerNews: null,
      reddit: null,
      realWorld,
      references: 1,
      affectedProducts: 1,
      weaknesses: 1,
      exploitMaturity: { stage: "No public signal in mock data", score: 10, scannerModule: false, exploitRefs: 0, publicCodeCount: 0, signals: [] },
      evidenceConfidence,
      cloudImpact
    },
    affected: [{ vendor: "Mock", product: "Mock Product", version: "Unknown", source: "Mock", cpe: "" }],
    weaknesses: [{ id: "CWE-20", source: "Mock", description: "Input validation placeholder" }],
    references: [{ url: `https://nvd.nist.gov/vuln/detail/${cve}`, title: "Mock reference", source: "Mock", tags: ["Mock"], type: "reference" }],
    evidence,
    timeline: [{ date: generatedAt, label: "Mock record generated", source: "VulnScope", detail: "Offline test mode" }],
    remediation: {
      summary: "Use live research mode for remediation guidance.",
      checklist: ["Run live research before making remediation decisions."],
      primaryLinks: buildSourceLinks(cve).slice(0, 2),
      advisoryRefs: [],
      plainText: `Remediation instructions for ${cve}\nRun live research before making remediation decisions.`
    },
    realWorld,
    exploitMaturity: { stage: "No public signal in mock data", score: 10, scannerModule: false, exploitRefs: 0, publicCodeCount: 0, signals: [] },
    evidenceConfidence,
    vendorPatch: { status: "Unknown", summary: "Mock mode has no vendor patch intelligence.", links: [] },
    cloudImpact,
    detectionGuidance: { checks: ["Run live mode before detection validation."], plainText: `Detection guidance for ${cve}\nRun live mode before detection validation.` },
    executiveBrief: { plainText: `Executive summary for ${cve}\nMock mode payload.` },
    ticketExport: { plainText: `[Medium] Validate ${cve}\nMock mode payload.` },
    riskAcceptance: { plainText: `Risk acceptance note for ${cve}\nMock mode payload.` },
    sourceResults,
    sourceLinks: buildSourceLinks(cve),
    analystActions: [{ id: "live-mode", label: "Run live research", priority: "High", detail: "Mock mode is for tests only." }]
  };
}

async function sourceTask(id, fn) {
  const source = sourceCatalog.find((item) => item.id === id);
  const started = Date.now();
  try {
    const data = await fn();
    const result = {
      id,
      label: source?.label || id,
      status: data?.skipped ? "skipped" : "ok",
      message: data?.skipped ? data.reason : data?.message || "Loaded",
      latencyMs: Date.now() - started,
      url: source?.url || "",
      data: data?.skipped ? null : data
    };
    recordSourceTelemetry(result);
    return result;
  } catch (error) {
    const result = {
      id,
      label: source?.label || id,
      status: "error",
      message: clientSafeError(error),
      latencyMs: Date.now() - started,
      url: source?.url || "",
      data: null
    };
    recordSourceTelemetry(result);
    return result;
  }
}

function recordSourceTelemetry(result) {
  sourceTelemetry.set(result.id, {
    status: result.status,
    message: result.message,
    latencyMs: result.latencyMs,
    lastCheckedAt: new Date().toISOString()
  });
}

async function fetchNvd(cve) {
  const headers = {
    accept: "application/json",
    "user-agent": "VulnScope/0.1"
  };
  if (process.env.NVD_API_KEY) {
    headers.apiKey = process.env.NVD_API_KEY;
  }
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=${encodeURIComponent(cve)}`;
  const json = await fetchJson(url, { headers });
  const item = json?.vulnerabilities?.[0]?.cve;
  if (!item) {
    throw new Error("No NVD record returned for this CVE.");
  }
  return item;
}

async function fetchCveOrg(cve) {
  const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cve)}`;
  const json = await fetchJson(url, {
    headers: {
      accept: "application/json",
      "user-agent": "VulnScope/0.1"
    }
  });
  if (!json?.cveMetadata?.cveId && !json?.id) {
    throw new Error("No CVE Services record returned.");
  }
  return {
    id: json.cveMetadata?.cveId || json.id,
    state: json.cveMetadata?.state,
    datePublished: json.cveMetadata?.datePublished,
    dateUpdated: json.cveMetadata?.dateUpdated,
    assignerShortName: json.cveMetadata?.assignerShortName,
    containers: json.containers || {}
  };
}

async function fetchEpss(cve) {
  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`;
  const json = await fetchJson(url, {
    headers: {
      accept: "application/json",
      "user-agent": "VulnScope/0.1"
    }
  });
  const item = json?.data?.[0];
  if (!item) {
    return {
      cve,
      epss: null,
      percentile: null,
      date: json?.date || null,
      message: "EPSS has no current score for this CVE."
    };
  }
  return {
    cve,
    epss: Number(item.epss),
    percentile: Number(item.percentile),
    date: item.date || json?.date || null
  };
}

async function fetchKev(cve) {
  const json = await fetchJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
    headers: {
      accept: "application/json",
      "user-agent": "VulnScope/0.1"
    }
  });
  const match = (json?.vulnerabilities || []).find((item) => normalizeCve(item.cveID) === cve);
  if (!match) {
    return {
      cve,
      listed: false,
      catalogVersion: json?.catalogVersion || null,
      dateReleased: json?.dateReleased || null,
      message: "CVE is not listed in the current CISA KEV catalog."
    };
  }
  return {
    listed: true,
    catalogVersion: json?.catalogVersion || null,
    dateReleased: json?.dateReleased || null,
    ...match
  };
}

async function fetchGitHubRepos(cve) {
  const headers = {
    accept: "application/vnd.github+json",
    "user-agent": "VulnScope/0.1"
  };
  if (process.env.GITHUB_TOKEN) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const query = encodeURIComponent(`${cve} in:name,description,readme`);
  const url = `https://api.github.com/search/repositories?q=${query}&sort=updated&order=desc&per_page=10`;
  const json = await fetchJson(url, { headers });
  return {
    totalCount: json.total_count || 0,
    incomplete: Boolean(json.incomplete_results),
    items: (json.items || []).map((repo) => ({
      id: repo.id,
      name: repo.full_name,
      url: repo.html_url,
      description: repo.description,
      stars: repo.stargazers_count || 0,
      forks: repo.forks_count || 0,
      language: repo.language,
      archived: Boolean(repo.archived),
      fork: Boolean(repo.fork),
      updatedAt: repo.updated_at,
      owner: repo.owner?.login
    }))
  };
}

async function fetchGitHubIssues(cve) {
  const headers = {
    accept: "application/vnd.github+json",
    "user-agent": "VulnScope/0.1"
  };
  if (process.env.GITHUB_TOKEN) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const query = encodeURIComponent(`${cve} in:title,body,comments`);
  const url = `https://api.github.com/search/issues?q=${query}&sort=updated&order=desc&per_page=10`;
  const json = await fetchJson(url, { headers });
  return {
    totalCount: json.total_count || 0,
    incomplete: Boolean(json.incomplete_results),
    items: (json.items || []).map((item) => ({
      id: item.id,
      title: item.title,
      url: item.html_url,
      state: item.state,
      comments: item.comments || 0,
      createdAt: item.created_at,
      updatedAt: item.updated_at,
      author: item.user?.login || "",
      repositoryUrl: item.repository_url || "",
      kind: item.pull_request ? "pull-request" : "issue"
    }))
  };
}

async function fetchGitHubAdvisories(cve) {
  const headers = {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "VulnScope/0.2"
  };
  if (process.env.GITHUB_TOKEN) {
    headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  const url = `https://api.github.com/advisories?cve_id=${encodeURIComponent(cve)}&per_page=10`;
  const json = await fetchJson(url, { headers });
  const items = Array.isArray(json) ? json : [];
  return {
    totalCount: items.length,
    items: items.map((item) => ({
      id: item.ghsa_id || item.cve_id || cve,
      cve: item.cve_id || cve,
      severity: item.severity || "unknown",
      summary: item.summary || "",
      description: item.description || "",
      publishedAt: item.published_at || null,
      updatedAt: item.updated_at || null,
      withdrawnAt: item.withdrawn_at || null,
      url: item.html_url || `https://github.com/advisories/${item.ghsa_id}`,
      references: (item.references || []).map((reference) => reference.url).filter(Boolean),
      vulnerabilities: (item.vulnerabilities || []).map((vulnerability) => ({
        ecosystem: vulnerability.package?.ecosystem || "",
        package: vulnerability.package?.name || "",
        vulnerableRange: vulnerability.vulnerable_version_range || "",
        firstPatchedVersion: vulnerability.first_patched_version || null
      }))
    }))
  };
}

async function fetchHackerNews(cve) {
  const url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(cve)}&hitsPerPage=10`;
  const json = await fetchJson(url, {
    headers: {
      accept: "application/json",
      "user-agent": "VulnScope/0.1"
    }
  });
  return {
    totalCount: json.nbHits || 0,
    page: json.page || 0,
    items: (json.hits || []).map((hit) => ({
      id: hit.objectID,
      title: hit.title || hit.story_title || hit.comment_text?.replace(/<[^>]+>/g, " ").slice(0, 140) || "Hacker News mention",
      url: hit.url || (hit.story_id ? `https://news.ycombinator.com/item?id=${hit.story_id}` : `https://news.ycombinator.com/item?id=${hit.objectID}`),
      hnUrl: `https://news.ycombinator.com/item?id=${hit.story_id || hit.objectID}`,
      author: hit.author || "",
      points: hit.points || 0,
      comments: hit.num_comments || 0,
      createdAt: hit.created_at,
      tags: hit._tags || []
    }))
  };
}

async function fetchReddit(cve) {
  const url = `https://www.reddit.com/search.json?q=${encodeURIComponent(cve)}&sort=relevance&limit=10&type=link`;
  let json;
  try {
    json = await fetchJson(url, {
      headers: {
        accept: "application/json",
        "user-agent": "VulnScope/0.1 by local analyst"
      }
    });
  } catch (error) {
    if (/403|blocked|forbidden/i.test(error.message)) {
      return {
        skipped: true,
        reason: "Reddit blocked unauthenticated public search from this environment."
      };
    }
    throw error;
  }
  const children = json?.data?.children || [];
  return {
    totalCount: children.length,
    after: json?.data?.after || null,
    items: children.map((child) => {
      const data = child.data || {};
      return {
        id: data.id,
        title: data.title || "Reddit mention",
        url: data.url || `https://www.reddit.com${data.permalink || ""}`,
        discussionUrl: data.permalink ? `https://www.reddit.com${data.permalink}` : data.url || "",
        subreddit: data.subreddit_name_prefixed || data.subreddit || "",
        author: data.author || "",
        score: data.score || 0,
        comments: data.num_comments || 0,
        createdAt: data.created_utc ? new Date(data.created_utc * 1000).toISOString() : null,
        over18: Boolean(data.over_18)
      };
    })
  };
}

async function fetchVulnCheck(cve) {
  if (!process.env.VULNCHECK_API_TOKEN) {
    return {
      skipped: true,
      reason: "Optional commercial exploit intelligence is unavailable."
    };
  }

  const headers = {
    accept: "application/json",
    authorization: `Bearer ${process.env.VULNCHECK_API_TOKEN}`,
    "user-agent": "VulnScope/0.1"
  };
  const exploitsUrl = `https://api.vulncheck.com/v3/index/exploits?cve=${encodeURIComponent(cve)}`;
  const initialAccessUrl = `https://api.vulncheck.com/v3/index/initial-access?cve=${encodeURIComponent(cve)}`;
  const [exploits, initialAccess] = await Promise.allSettled([
    fetchJson(exploitsUrl, { headers }),
    fetchJson(initialAccessUrl, { headers })
  ]);

  const exploitData = unwrapVulnCheckResult(exploits);
  const initialAccessData = unwrapVulnCheckResult(initialAccess);

  return {
    exploits: exploitData,
    initialAccess: initialAccessData,
    message: "Loaded optional VulnCheck data."
  };
}

function unwrapVulnCheckResult(result) {
  if (result.status !== "fulfilled") {
    return {
      error: result.reason?.message || "Request failed"
    };
  }
  if (Array.isArray(result.value)) {
    return result.value;
  }
  if (Array.isArray(result.value?.data)) {
    return result.value.data;
  }
  return result.value;
}

function normalizeEnrichmentPackages(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  const packages = [];
  for (const item of value.slice(0, enrichmentPackageMax)) {
    if (!item || typeof item !== "object") continue;
    const purl = boundedString(item.purl, 1000);
    const ecosystem = boundedString(item.ecosystem, 80);
    const name = boundedString(item.name, 300);
    const version = boundedString(item.version, 200);
    const validPurl = /^pkg:[a-z0-9.+-]+\/[a-z0-9._~!$&'()*+,;=:@%/-]+/i.test(purl) ? purl : "";
    if (!validPurl && (!ecosystem || !name || !version)) continue;
    const key = validPurl || `${ecosystem}:${name}@${version}`;
    if (seen.has(key.toLowerCase())) continue;
    seen.add(key.toLowerCase());
    packages.push({
      key,
      purl: validPurl,
      ecosystem,
      name,
      version,
      fileName: boundedString(item.fileName, 300)
    });
  }
  return packages;
}

function boundedString(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

async function enrichPackages(packages) {
  const generatedAt = new Date().toISOString();
  const source = await sourceTask("osv", () => fetchOsvPackageMatches(packages));
  return {
    generatedAt,
    packageCount: packages.length,
    vulnerabilityCount: source.data?.vulnerabilityCount || 0,
    truncated: Boolean(source.data?.truncated),
    packages: source.data?.packages || packages.map((pkg) => ({ ...pkg, vulnerabilities: [] })),
    sourceResults: [{
      id: source.id,
      label: source.label,
      status: source.status,
      message: source.message,
      latencyMs: source.latencyMs,
      url: source.url
    }]
  };
}

async function fetchOsvPackageMatches(packages) {
  const queries = packages.map(buildOsvQuery);
  const batch = await fetchJson("https://api.osv.dev/v1/querybatch", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "VulnScope/0.2"
    },
    body: JSON.stringify({ queries })
  });
  if (!Array.isArray(batch?.results) || batch.results.length !== packages.length) {
    throw new Error("No OSV package results returned.");
  }

  const ids = [...new Set(batch.results.flatMap((result) => (result?.vulns || []).map((vulnerability) => vulnerability.id).filter(Boolean)))];
  const selectedIds = ids.slice(0, enrichmentVulnerabilityMax);
  const detailRows = [];
  for (let index = 0; index < selectedIds.length; index += outboundConcurrency) {
    const group = selectedIds.slice(index, index + outboundConcurrency);
    detailRows.push(...await Promise.all(group.map(async (id) => {
      try {
        return [id, await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
          headers: { accept: "application/json", "user-agent": "VulnScope/0.2" }
        })];
      } catch {
        return [id, null];
      }
    })));
  }
  const details = new Map(detailRows);
  const enriched = packages.map((pkg, index) => ({
    ...pkg,
    vulnerabilities: (batch.results[index]?.vulns || [])
      .filter((item) => selectedIds.includes(item.id))
      .map((item) => normalizeOsvVulnerability(details.get(item.id), item))
  }));
  return {
    packages: enriched,
    vulnerabilityCount: new Set(enriched.flatMap((pkg) => pkg.vulnerabilities.map((item) => item.id))).size,
    truncated: ids.length > selectedIds.length,
    message: `Matched ${ids.length} OSV record${ids.length === 1 ? "" : "s"} across ${packages.length} package${packages.length === 1 ? "" : "s"}.`
  };
}

export function buildOsvQuery(pkg) {
  if (pkg.purl) {
    const purlIncludesVersion = /@[^/?#]+(?:[?#]|$)/.test(pkg.purl);
    return {
      ...(!purlIncludesVersion && pkg.version ? { version: pkg.version } : {}),
      package: { purl: pkg.purl }
    };
  }
  return {
    version: pkg.version,
    package: {
      ecosystem: pkg.ecosystem,
      name: pkg.name
    }
  };
}

function normalizeOsvVulnerability(detail, fallback = {}) {
  const affected = (Array.isArray(detail?.affected) ? detail.affected : []).slice(0, 12);
  const aliases = (Array.isArray(detail?.aliases) ? detail.aliases : []).slice(0, 50).map((value) => boundedString(value, 120));
  const cves = aliases.filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value));
  const fixedVersions = [...new Set(affected.flatMap((entry) => (entry.ranges || [])
    .slice(0, 8)
    .flatMap((range) => (range.events || []).slice(0, 50).map((event) => boundedString(event.fixed, 200)).filter(Boolean))))].slice(0, 100);
  return {
    id: boundedString(detail?.id || fallback.id || "Unknown", 120),
    aliases,
    cves,
    summary: boundedString(detail?.summary, 1000),
    details: boundedString(detail?.details, 4000),
    severity: boundedString(detail?.database_specific?.severity, 40),
    published: detail?.published || null,
    modified: detail?.modified || fallback.modified || null,
    withdrawn: detail?.withdrawn || null,
    fixedVersions,
    affected: affected.map(normalizeOsvAffectedEntry),
    references: (detail?.references || []).slice(0, 50).map((reference) => ({
      type: boundedString(reference.type || "WEB", 40),
      url: safeHttpUrl(reference.url)
    })).filter((reference) => reference.url)
  };
}

function normalizeOsvAffectedEntry(entry) {
  return {
    package: {
      ecosystem: boundedString(entry?.package?.ecosystem, 80),
      name: boundedString(entry?.package?.name, 300),
      purl: boundedString(entry?.package?.purl, 1000)
    },
    ranges: (entry?.ranges || []).slice(0, 8).map((range) => ({
      type: boundedString(range?.type, 40),
      repo: safeHttpUrl(range?.repo),
      events: (range?.events || []).slice(0, 50).map((event) => Object.fromEntries(
        ["introduced", "fixed", "last_affected", "limit"]
          .filter((key) => event?.[key] !== undefined)
          .map((key) => [key, boundedString(event[key], 200)])
      ))
    })),
    versions: (entry?.versions || []).slice(0, 100).map((value) => boundedString(value, 200))
  };
}

function safeHttpUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

async function fetchJson(url, options = {}) {
  return withOutboundSlot(async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      const text = await readLimitedResponseText(response);
      if (!response.ok) {
        throw new Error(`Source returned ${response.status} ${response.statusText || "HTTP error"}.`);
      }
      if (!text.trim()) {
        return null;
      }
      try {
        return JSON.parse(text);
      } catch {
        throw new Error("Source returned invalid JSON.");
      }
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("Request timed out.");
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  });
}

function normalizeCve(value) {
  const normalized = String(value || "").trim().toUpperCase();
  return /^CVE-\d{4}-\d{4,}$/.test(normalized) ? normalized : "";
}

function pickTitle(cve, nvd, cveOrg, kev) {
  const cnaTitle = cveOrg?.containers?.cna?.title;
  if (cnaTitle) return cnaTitle;
  if (kev?.listed && kev.vulnerabilityName) return kev.vulnerabilityName;
  const description = pickDescription(nvd, cveOrg, kev);
  if (description) return sentence(description).slice(0, 140);
  return `${cve} investigation`;
}

function pickDescription(nvd, cveOrg, kev) {
  const nvdDescription = nvd?.descriptions?.find((item) => item.lang === "en")?.value;
  const cnaDescription = cveOrg?.containers?.cna?.descriptions?.find((item) => item.lang === "en")?.value;
  return nvdDescription || cnaDescription || kev?.shortDescription || "";
}

function extractCvss(nvd, cveOrg) {
  const metrics = nvd?.metrics || {};
  const nvdMetric =
    metrics.cvssMetricV40?.[0] ||
    metrics.cvssMetricV31?.[0] ||
    metrics.cvssMetricV30?.[0] ||
    metrics.cvssMetricV2?.[0];

  if (nvdMetric?.cvssData) {
    return {
      source: nvdMetric.source || "NVD",
      version: nvdMetric.cvssData.version || "unknown",
      score: Number(nvdMetric.cvssData.baseScore),
      severity: nvdMetric.cvssData.baseSeverity || nvdMetric.baseSeverity || severityFromScore(nvdMetric.cvssData.baseScore),
      vector: nvdMetric.cvssData.vectorString || "",
      exploitabilityScore: nvdMetric.exploitabilityScore ?? null,
      impactScore: nvdMetric.impactScore ?? null
    };
  }

  const cnaMetrics = cveOrg?.containers?.cna?.metrics || [];
  for (const metric of cnaMetrics) {
    const cvss = metric.cvssV4_0 || metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV2_0;
    if (cvss) {
      return {
        source: "CVE CNA",
        version: cvss.version || "unknown",
        score: Number(cvss.baseScore),
        severity: cvss.baseSeverity || severityFromScore(cvss.baseScore),
        vector: cvss.vectorString || "",
        exploitabilityScore: null,
        impactScore: null
      };
    }
  }

  return null;
}

function extractAffectedProducts(nvd, cveOrg, kev) {
  const affected = [];

  for (const item of cveOrg?.containers?.cna?.affected || []) {
    const versions = (item.versions || [])
      .map((version) => {
        if (version.version && version.status) return `${version.version} (${version.status})`;
        return version.version || version.lessThan || version.status || "";
      })
      .filter(Boolean)
      .slice(0, 5);
    affected.push({
      vendor: item.vendor || kev?.vendorProject || "Unknown",
      product: item.product || kev?.product || "Unknown",
      version: versions.join(", ") || "See vendor advisory",
      source: "CVE CNA",
      cpe: ""
    });
  }

  const cpes = [];
  for (const node of nvd?.configurations || []) {
    collectCpeMatches(node, cpes);
  }
  for (const match of cpes.filter((item) => item.vulnerable).slice(0, 40)) {
    const parsed = parseCpe(match.criteria || match.matchCriteriaId || "");
    affected.push({
      vendor: parsed.vendor || "Unknown",
      product: parsed.product || "Unknown",
      version: parsed.version || "Any matching version",
      source: "NVD CPE",
      cpe: match.criteria || ""
    });
  }

  if (kev?.listed) {
    affected.push({
      vendor: kev.vendorProject || "Unknown",
      product: kev.product || "Unknown",
      version: "Known exploited product family",
      source: "CISA KEV",
      cpe: ""
    });
  }

  return uniqueAffected(affected).slice(0, 50);
}

function collectCpeMatches(node, out) {
  for (const match of node.cpeMatch || []) out.push(match);
  for (const child of node.nodes || []) collectCpeMatches(child, out);
}

function parseCpe(cpe) {
  const parts = cpe.split(":");
  if (parts.length < 6) return {};
  return {
    vendor: humanizeCpePart(parts[3]),
    product: humanizeCpePart(parts[4]),
    version: parts[5] && parts[5] !== "*" ? humanizeCpePart(parts[5]) : ""
  };
}

function humanizeCpePart(value) {
  return decodeURIComponent(String(value || "").replace(/\\:/g, ":")).replace(/_/g, " ");
}

function uniqueAffected(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.vendor}|${item.product}|${item.version}|${item.cpe}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function extractWeaknesses(nvd, cveOrg, kev) {
  const values = [];
  for (const weakness of nvd?.weaknesses || []) {
    for (const description of weakness.description || []) {
      if (description.lang === "en" && description.value) {
        values.push({
          id: description.value,
          source: weakness.source || "NVD"
        });
      }
    }
  }
  for (const problem of cveOrg?.containers?.cna?.problemTypes || []) {
    for (const description of problem.descriptions || []) {
      if (description.cweId || description.description) {
        values.push({
          id: description.cweId || description.description,
          source: "CVE CNA",
          description: description.description || ""
        });
      }
    }
  }
  for (const cwe of kev?.cwes || []) {
    values.push({ id: cwe, source: "CISA KEV" });
  }
  const seen = new Set();
  return values.filter((item) => {
    const key = item.id.toLowerCase();
    if (!item.id || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function extractNvdReferences(nvd) {
  return (nvd?.references || []).map((reference) => ({
    url: reference.url,
    title: reference.url,
    source: reference.source || "NVD",
    tags: reference.tags || [],
    type: classifyReference(reference.url, reference.tags)
  }));
}

function extractCveOrgReferences(cveOrg) {
  return (cveOrg?.containers?.cna?.references || []).map((reference) => ({
    url: reference.url,
    title: reference.name || reference.url,
    source: "CVE CNA",
    tags: reference.tags || [],
    type: classifyReference(reference.url, reference.tags)
  }));
}

function extractKevReferences(kev) {
  if (!kev?.notes) return [];
  const urls = String(kev.notes).match(/https?:\/\/[^\s,)]+/g) || [];
  return urls.map((url) => ({
    url,
    title: url,
    source: "CISA KEV",
    tags: ["Third Party Advisory"],
    type: classifyReference(url, ["Third Party Advisory"])
  }));
}

function extractGitHubAdvisoryReferences(advisories) {
  return (advisories?.items || []).flatMap((advisory) => [
    {
      url: advisory.url,
      title: advisory.summary || advisory.id,
      source: "GitHub Advisory Database",
      tags: ["GitHub Advisory", advisory.severity].filter(Boolean),
      type: "advisory"
    },
    ...(advisory.references || []).map((url) => ({
      url,
      title: url,
      source: "GitHub Advisory Database",
      tags: ["GitHub Advisory"],
      type: classifyReference(url, ["GitHub Advisory"])
    }))
  ]);
}

function classifyReference(url = "", tags = []) {
  const joined = `${tags.join(" ")} ${url}`.toLowerCase();
  if (/patch|release|update|fixed|commit|pull/.test(joined)) return "patch";
  if (/exploit|poc|metasploit|packetstorm|0day|github/.test(joined)) return "exploit";
  if (/advisory|vendor|security/.test(joined)) return "advisory";
  if (/mitigation|workaround/.test(joined)) return "mitigation";
  return "reference";
}

function dedupeByUrl(items) {
  const seen = new Set();
  return items
    .filter((item) => item.url)
    .filter((item) => {
      const key = item.url.replace(/\/$/, "").toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function buildEvidence(cve, context) {
  const evidence = [];
  const { nvd, cveOrg, epss, kev, github, githubIssues, githubAdvisories, hackerNews, reddit, vulncheck, references } = context;

  if (nvd) {
    evidence.push({
      id: "nvd-record",
      type: "primary-record",
      source: "NVD",
      title: "NVD record is available",
      url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      description: nvd.vulnStatus ? `NVD status: ${nvd.vulnStatus}` : "NVD returned a vulnerability record.",
      date: nvd.published,
      confidence: "high",
      tags: ["official", "metadata"]
    });
  }

  if (cveOrg) {
    evidence.push({
      id: "cve-record",
      type: "primary-record",
      source: "CVE Services",
      title: "CVE Services record is available",
      url: `https://www.cve.org/CVERecord?id=${cve}`,
      description: cveOrg.assignerShortName ? `Assigned by ${cveOrg.assignerShortName}` : "CVE Services returned the CNA record.",
      date: cveOrg.datePublished,
      confidence: "high",
      tags: ["official", "cna"]
    });
  }

  if (kev?.listed) {
    evidence.push({
      id: "cisa-kev",
      type: "exploitation",
      source: "CISA KEV",
      title: "Listed in CISA Known Exploited Vulnerabilities",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      description: `${kev.vendorProject || "Vendor"} ${kev.product || "product"} is known exploited. Required action: ${kev.requiredAction || "see CISA guidance"}`,
      date: kev.dateAdded,
      confidence: "high",
      tags: ["known-exploited", kev.knownRansomwareCampaignUse === "Known" ? "ransomware" : ""].filter(Boolean)
    });
  }

  if (epss?.epss !== null && epss?.epss !== undefined) {
    evidence.push({
      id: "epss-score",
      type: "probability",
      source: "FIRST EPSS",
      title: `EPSS probability ${formatPercent(epss.epss)}`,
      url: `https://api.first.org/data/v1/epss?cve=${cve}`,
      description: `Percentile ${formatPercent(epss.percentile)} based on the latest EPSS feed.`,
      date: epss.date,
      confidence: "medium",
      tags: ["exploit-probability"]
    });
  }

  for (const reference of references.filter((item) => item.type === "exploit").slice(0, 12)) {
    evidence.push({
      id: `ref-${hash(reference.url)}`,
      type: "exploit-reference",
      source: reference.source,
      title: reference.title || reference.url,
      url: reference.url,
      description: `Reference tagged or classified as ${reference.type}.`,
      date: null,
      confidence: reference.tags?.length ? "medium" : "low",
      tags: reference.tags?.length ? reference.tags : ["exploit-reference"]
    });
  }

  for (const repo of github?.items || []) {
    evidence.push({
      id: `github-${repo.id}`,
      type: "public-code",
      source: "GitHub",
      title: repo.name,
      url: repo.url,
      description: repo.description || `Repository matching ${cve}. Stars: ${repo.stars}. Forks: ${repo.forks}.`,
      date: repo.updatedAt,
      confidence: repo.stars > 20 ? "medium" : "low",
      tags: [repo.language, repo.archived ? "archived" : "", repo.fork ? "fork" : ""].filter(Boolean)
    });
  }

  for (const item of githubIssues?.items || []) {
    evidence.push({
      id: `github-discussion-${item.id}`,
      type: "developer-chatter",
      source: "GitHub Issues and PRs",
      title: item.title,
      url: item.url,
      description: `${item.kind === "pull-request" ? "Pull request" : "Issue"} mentioning ${cve}. Comments: ${item.comments}. State: ${item.state}.`,
      date: item.updatedAt,
      confidence: item.comments > 5 ? "medium" : "low",
      tags: [item.kind, item.state, item.author].filter(Boolean)
    });
  }

  for (const advisory of githubAdvisories?.items || []) {
    evidence.push({
      id: `github-advisory-${advisory.id}`,
      type: "primary-record",
      source: "GitHub Advisory Database",
      title: advisory.summary || advisory.id,
      url: advisory.url,
      description: advisory.withdrawnAt
        ? `Withdrawn advisory. ${advisory.description || "Review the advisory history before using it."}`
        : advisory.description || `${advisory.vulnerabilities.length} affected package range record${advisory.vulnerabilities.length === 1 ? "" : "s"}.`,
      date: advisory.updatedAt || advisory.publishedAt,
      confidence: "high",
      tags: [advisory.id, advisory.severity, advisory.withdrawnAt ? "withdrawn" : "reviewed"].filter(Boolean)
    });
  }

  for (const item of hackerNews?.items || []) {
    evidence.push({
      id: `hn-${item.id}`,
      type: "community-chatter",
      source: "Hacker News",
      title: item.title,
      url: item.hnUrl || item.url,
      description: `Public Hacker News mention. Points: ${item.points}. Comments: ${item.comments}.`,
      date: item.createdAt,
      confidence: item.comments > 10 || item.points > 25 ? "medium" : "low",
      tags: ["public-discussion", item.author].filter(Boolean)
    });
  }

  for (const item of reddit?.items || []) {
    evidence.push({
      id: `reddit-${item.id}`,
      type: "community-chatter",
      source: "Reddit",
      title: item.title,
      url: item.discussionUrl || item.url,
      description: `Public Reddit mention${item.subreddit ? ` in ${item.subreddit}` : ""}. Score: ${item.score}. Comments: ${item.comments}.`,
      date: item.createdAt,
      confidence: item.comments > 10 || item.score > 25 ? "medium" : "low",
      tags: ["public-discussion", item.subreddit].filter(Boolean)
    });
  }

  for (const item of normalizeVulnCheckExploits(vulncheck).slice(0, 12)) {
    evidence.push({
      id: `vulncheck-${hash(item.url || item.name)}`,
      type: "commercial-intel",
      source: item.refsource || "VulnCheck",
      title: item.name || item.url || "VulnCheck exploit reference",
      url: item.url || "",
      description: [item.exploit_maturity, item.exploit_availability, item.exploit_type].filter(Boolean).join(" / "),
      date: item.date_added,
      confidence: item.exploit_maturity === "weaponized" ? "high" : "medium",
      tags: [item.exploit_maturity, item.exploit_availability, item.exploit_type].filter(Boolean)
    });
  }

  return evidence.sort((a, b) => evidencePriority(b) - evidencePriority(a));
}

function enrichEvidenceConfidence(evidence) {
  return evidence.map((item) => ({
    ...item,
    reputation: sourceReputationForEvidence(item),
    credibility: classifyEvidenceCredibility(item)
  }));
}

function classifyEvidenceCredibility(item) {
  const reputation = item.reputation || sourceReputationForEvidence(item);
  if (reputation.trust === "confirmed") return "Confirmed";
  if (reputation.trust === "strong") return "Strong signal";
  if (reputation.trust === "noise-prone") return item.confidence === "medium" ? "Lead" : "Noise-prone";
  if (["CISA KEV", "NVD", "CVE Services"].includes(item.source)) {
    return "Confirmed";
  }
  if (item.type === "commercial-intel" || item.confidence === "high") {
    return "Strong signal";
  }
  if (["probability", "exploit-reference", "public-code"].includes(item.type)) {
    return "Lead";
  }
  if (/chatter/.test(item.type)) {
    return item.confidence === "medium" ? "Lead" : "Noise-prone";
  }
  return "Lead";
}

function sourceReputationForEvidence(item) {
  const source = String(item.source || "").toLowerCase();
  if (source.includes("cisa kev")) {
    return {
      tier: "Confirmed exploitation",
      trust: "confirmed",
      guidance: "Authoritative signal that exploitation has been confirmed by CISA."
    };
  }
  if (source === "nvd") {
    return {
      tier: "Official metadata",
      trust: "confirmed",
      guidance: "Authoritative vulnerability metadata; still validate affected versions against vendor guidance."
    };
  }
  if (source.includes("cve services")) {
    return {
      tier: "CNA record",
      trust: "confirmed",
      guidance: "Primary CVE program record from the CNA or CVE Services."
    };
  }
  if (source.includes("github advisory")) {
    return {
      tier: "Reviewed package advisory",
      trust: "confirmed",
      guidance: "Reviewed package advisory data with affected-version and patch-range context."
    };
  }
  if (source.includes("first epss")) {
    return {
      tier: "Predictive model",
      trust: "lead",
      guidance: "Exploit probability model; useful for prioritization but not proof of exploitation."
    };
  }
  if (item.type === "commercial-intel" || source.includes("vulncheck")) {
    return {
      tier: "Commercial intelligence",
      trust: "strong",
      guidance: "Exploit intelligence source; validate details against your environment before action."
    };
  }
  if (item.type === "public-code" || source === "github") {
    return {
      tier: "Public code lead",
      trust: "lead",
      guidance: "Repository match that may be useful, unrelated, copied, archived, or proof-of-concept code."
    };
  }
  if (source.includes("github issues")) {
    return {
      tier: "Developer discussion",
      trust: "noise-prone",
      guidance: "Public issue or pull request mention; review manually before treating it as evidence."
    };
  }
  if (source.includes("hacker news") || source.includes("reddit") || /chatter/.test(item.type)) {
    return {
      tier: "Community chatter",
      trust: "noise-prone",
      guidance: "Public discussion lead; useful for awareness but not authoritative."
    };
  }
  if (item.type === "exploit-reference") {
    return {
      tier: "External exploit reference",
      trust: item.confidence === "medium" ? "lead" : "noise-prone",
      guidance: "Reference classified as exploit-related; verify credibility and applicability."
    };
  }
  return {
    tier: "External reference",
    trust: "lead",
    guidance: "Supplemental reference; validate before making remediation decisions."
  };
}

function buildEvidenceConfidenceSummary(evidence) {
  const counts = { Confirmed: 0, "Strong signal": 0, Lead: 0, "Noise-prone": 0 };
  for (const item of evidence) {
    counts[item.credibility] = (counts[item.credibility] || 0) + 1;
  }
  return {
    counts,
    summary: `${counts.Confirmed || 0} confirmed, ${counts["Strong signal"] || 0} strong signal, ${counts.Lead || 0} lead, ${counts["Noise-prone"] || 0} noise-prone evidence items.`,
    guidance: "Use confirmed and strong-signal evidence for prioritization. Treat public code, GitHub issues, Hacker News, and Reddit as leads until manually validated."
  };
}

function normalizeVulnCheckExploits(vulncheck) {
  const rows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const first = rows[0] || {};
  if (Array.isArray(first.exploits)) return first.exploits;
  if (Array.isArray(rows)) return rows.flatMap((row) => row.exploits || []);
  return [];
}

function evidencePriority(item) {
  let score = 0;
  if (item.confidence === "high") score += 40;
  if (item.confidence === "medium") score += 20;
  if (/exploitation|commercial|exploit|public-code/.test(item.type)) score += 25;
  if (/chatter/.test(item.type)) score += 8;
  if (item.date) score += 5;
  return score;
}

function buildTimeline({ nvd, cveOrg, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, references }) {
  const events = [];
  addEvent(events, cveOrg?.datePublished, "CVE published by CNA", "CVE Services", cveOrg?.assignerShortName || "");
  addEvent(events, nvd?.published, "NVD published record", "NVD", nvd?.vulnStatus || "");
  addEvent(events, nvd?.lastModified, "NVD record modified", "NVD", "");
  addEvent(events, cveOrg?.dateUpdated, "CVE record updated", "CVE Services", "");
  if (kev?.listed) {
    addEvent(events, kev.dateAdded, "Added to CISA KEV", "CISA KEV", kev.requiredAction || "");
    addEvent(events, kev.dueDate, "CISA remediation due date", "CISA KEV", "");
  }
  addEvent(events, epss?.date, "Latest EPSS score", "FIRST EPSS", epss?.epss ? formatPercent(epss.epss) : "");

  const exploitRefs = references.filter((item) => item.type === "exploit").slice(0, 5);
  for (const reference of exploitRefs) {
    addEvent(events, null, "Exploit reference found", reference.source, reference.url);
  }

  for (const repo of github?.items?.slice(0, 5) || []) {
    addEvent(events, repo.updatedAt, "GitHub repository updated", "GitHub", repo.name);
  }

  for (const item of githubIssues?.items?.slice(0, 5) || []) {
    addEvent(events, item.updatedAt, "GitHub discussion updated", "GitHub Issues and PRs", item.title);
  }

  for (const item of hackerNews?.items?.slice(0, 4) || []) {
    addEvent(events, item.createdAt, "Hacker News mention", "Hacker News", item.title);
  }

  for (const item of reddit?.items?.slice(0, 4) || []) {
    addEvent(events, item.createdAt, "Reddit mention", item.subreddit || "Reddit", item.title);
  }

  const vulncheckRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const first = vulncheckRows[0] || {};
  const timeline = first.timeline || {};
  addEvent(events, timeline.first_exploit_published, "First exploit published", "VulnCheck", "");
  addEvent(events, timeline.first_reported_threat_actor, "First threat actor reporting", "VulnCheck", "");
  addEvent(events, timeline.first_reported_ransomware, "First ransomware reporting", "VulnCheck", "");

  return events.sort((a, b) => {
    if (!a.date && !b.date) return 0;
    if (!a.date) return 1;
    if (!b.date) return -1;
    return new Date(a.date) - new Date(b.date);
  });
}

function addEvent(events, date, label, source, detail) {
  if (!date && !detail) return;
  events.push({
    id: `${label}-${source}-${date || hash(detail)}`,
    date: date || null,
    label,
    source,
    detail: detail || ""
  });
}

function buildRemediation(cve, { kev, references, affected, title, cvss }) {
  const advisoryRefs = references.filter((item) => ["patch", "advisory", "mitigation"].includes(item.type)).slice(0, 14);
  const primaryLinks = buildRemediationLinks(cve, advisoryRefs, references);
  const steps = [];
  if (kev?.listed) {
    steps.push({
      priority: "required",
      title: "Follow CISA required action",
      detail: kev.requiredAction || "Apply vendor updates or mitigations according to CISA guidance.",
      dueDate: kev.dueDate || null,
      source: "CISA KEV"
    });
  }
  if (advisoryRefs.length) {
    steps.push({
      priority: "high",
      title: "Review vendor advisories and patch notes",
      detail: `${advisoryRefs.length} patch, mitigation, or advisory reference${advisoryRefs.length === 1 ? "" : "s"} were found.`,
      dueDate: null,
      source: "References"
    });
  }
  if (affected.length) {
    steps.push({
      priority: "medium",
      title: "Validate exposure against affected products",
      detail: `Match inventories against ${affected.length} affected product indicator${affected.length === 1 ? "" : "s"}.`,
      dueDate: null,
      source: "NVD/CNA"
    });
  }
  steps.push({
    priority: "medium",
    title: "Check scanner coverage and compensating controls",
    detail: "Confirm authenticated scanner plugins, EDR detections, WAF rules, and segmentation controls before closing the case.",
    dueDate: null,
    source: "Analyst workflow"
  });

  return {
    steps,
    advisoryRefs,
    plainText: buildPlainTextRemediation(cve, { title, cvss, kev, affected, advisoryRefs, primaryLinks }),
    primaryLinks,
    reportLink: `https://nvd.nist.gov/vuln/detail/${cve}`
  };
}

function buildRemediationLinks(cve, advisoryRefs, references) {
  const links = [
    { label: "NVD CVE Record", url: `https://nvd.nist.gov/vuln/detail/${cve}` },
    { label: "CVE.org Record", url: `https://www.cve.org/CVERecord?id=${cve}` },
    { label: "CISA KEV Catalog", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }
  ];
  for (const reference of advisoryRefs.slice(0, 6)) {
    links.push({
      label: readableLinkLabel(reference),
      url: reference.url
    });
  }
  for (const reference of references.filter((item) => item.type === "exploit").slice(0, 3)) {
    links.push({
      label: `Exploit reference - ${readableLinkLabel(reference)}`,
      url: reference.url
    });
  }
  return dedupeByUrl(links).slice(0, 12);
}

function buildPlainTextRemediation(cve, { title, cvss, kev, affected, advisoryRefs, primaryLinks }) {
  const lines = [];
  const affectedLead = affected.slice(0, 5);
  lines.push(`Remediation instructions for ${cve}`);
  lines.push(`Title: ${title || "See CVE record"}`);
  if (cvss?.score) {
    lines.push(`Severity: ${cvss.severity || "Unknown"} / CVSS ${cvss.score}${cvss.vector ? ` / ${cvss.vector}` : ""}`);
  }
  if (kev?.listed) {
    lines.push(`Known exploited: Yes. CISA KEV date added: ${kev.dateAdded || "unknown"}${kev.knownRansomwareCampaignUse === "Known" ? ". Known ransomware campaign use: yes." : "."}`);
  }
  lines.push("");
  lines.push("Recommended action plan:");
  lines.push("1. Identify exposure: search asset inventory, vulnerability scanners, EDR/software inventory, CMDB, container images, and internet-facing services for the affected product/version.");
  if (affectedLead.length) {
    lines.push("   Affected product signals to check:");
    for (const item of affectedLead) {
      lines.push(`   - ${item.vendor} ${item.product}: ${item.version || item.cpe || "see vendor advisory"} (${item.source})`);
    }
  }
  if (kev?.listed && kev.requiredAction) {
    lines.push(`2. Follow CISA KEV guidance: ${kev.requiredAction}`);
  } else {
    lines.push("2. Review the vendor advisory and apply the vendor-provided fixed version or mitigation.");
  }
  lines.push("3. Prioritize remediation for internet-facing, externally reachable, privileged, production, and business-critical systems.");
  lines.push("4. If patching cannot be completed immediately, apply vendor-approved mitigations or temporary compensating controls, then document the exception owner and expiration date.");
  lines.push("5. Validate remediation: rescan the asset, verify the installed/fixed version, confirm scanner plugin coverage, and capture evidence in the ticket.");
  lines.push("6. Review monitoring: check EDR/SIEM/WAF/proxy logs for exploit attempts, suspicious child processes, newly created accounts, web shells, unusual outbound traffic, or other indicators described by vendor/security advisories.");
  lines.push("7. Close the remediation ticket only after affected assets are patched or mitigated, validation evidence is attached, and any residual risk is accepted by the system owner.");
  if (kev?.listed && kev.dueDate) {
    lines.push(`8. Target completion no later than the CISA KEV due date: ${kev.dueDate}.`);
  }
  lines.push("");
  lines.push("Useful links:");
  for (const link of primaryLinks) {
    lines.push(`- ${link.label}: ${link.url}`);
  }
  if (!advisoryRefs.length) {
    lines.push("- No vendor patch reference was automatically classified. Manually review the CVE.org/NVD references and the vendor security advisory page before closing.");
  }
  return lines.join("\n");
}

function readableLinkLabel(reference) {
  if (reference.label) return reference.label;
  const title = reference.title && reference.title !== reference.url ? reference.title : "";
  if (title) return title.slice(0, 90);
  try {
    const url = new URL(reference.url);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return reference.source || "Reference";
  }
}

function buildRealWorldAssessment(cve, { epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, references, evidence }) {
  const vcRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const vcFirst = vcRows[0] || {};
  const exploitRefCount = references.filter((item) => item.type === "exploit").length;
  const publicCodeCount = github?.totalCount || 0;
  const githubDiscussionCount = githubIssues?.totalCount || 0;
  const hackerNewsCount = hackerNews?.totalCount || 0;
  const redditCount = reddit?.totalCount || 0;
  const chatterCount = githubDiscussionCount + hackerNewsCount + redditCount;
  const publicExploitSignals = exploitRefCount + publicCodeCount + normalizeVulnCheckExploits(vulncheck).length;
  const engagedChatter = countEngagedChatter({ githubIssues, hackerNews, reddit });
  const signals = [];
  let score = 0;

  if (kev?.listed) {
    score += 45;
    signals.push({
      label: "Confirmed exploited",
      status: "High confidence",
      source: "CISA KEV",
      detail: `CISA lists ${cve} as known exploited${kev.knownRansomwareCampaignUse === "Known" ? " with known ransomware campaign use" : ""}.`,
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    });
  } else if (kev) {
    signals.push({
      label: "No KEV listing",
      status: "Informational",
      source: "CISA KEV",
      detail: "The current CISA KEV feed did not list this CVE.",
      url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    });
  }

  if (vcFirst.weaponized_exploit_found) {
    score += 35;
    signals.push({
      label: "Weaponized exploit signal",
      status: "High confidence",
      source: "VulnCheck",
      detail: "Optional VulnCheck data reports a weaponized exploit signal.",
      url: `https://www.vulncheck.com/xdb?q=${encodeURIComponent(cve)}`
    });
  } else if (vcFirst.public_exploit_found || vcFirst.commercial_exploit_found) {
    score += 22;
    signals.push({
      label: "Exploit available",
      status: "Medium confidence",
      source: "VulnCheck",
      detail: "Optional VulnCheck data reports public or commercial exploit availability.",
      url: `https://www.vulncheck.com/xdb?q=${encodeURIComponent(cve)}`
    });
  }

  if (epss?.epss >= 0.9) {
    score += 18;
    signals.push({
      label: "Very high exploitation probability",
      status: "Model signal",
      source: "FIRST EPSS",
      detail: `EPSS is ${formatPercent(epss.epss)} at percentile ${formatPercent(epss.percentile)}.`,
      url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`
    });
  } else if (epss?.epss >= 0.1) {
    score += 8;
    signals.push({
      label: "Notable exploitation probability",
      status: "Model signal",
      source: "FIRST EPSS",
      detail: `EPSS is ${formatPercent(epss.epss)} at percentile ${formatPercent(epss.percentile)}.`,
      url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`
    });
  }

  if (exploitRefCount) {
    score += Math.min(14, exploitRefCount * 4);
    signals.push({
      label: "Exploit references found",
      status: "Needs validation",
      source: "NVD/CNA references",
      detail: `${exploitRefCount} reference${exploitRefCount === 1 ? "" : "s"} were tagged or classified as exploit-related.`,
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`
    });
  }

  if (publicCodeCount) {
    score += publicCodeCount > 25 ? 12 : 6;
    signals.push({
      label: "Public code leads",
      status: "Needs validation",
      source: "GitHub repositories",
      detail: `${publicCodeCount} GitHub repository match${publicCodeCount === 1 ? "" : "es"} mention this CVE.`,
      url: `https://github.com/search?q=${encodeURIComponent(cve)}&type=repositories`
    });
  }

  if (chatterCount) {
    score += chatterCount > 25 ? 10 : chatterCount > 5 ? 6 : 3;
    signals.push({
      label: "Public discussion",
      status: engagedChatter ? "Active chatter" : "Low-volume chatter",
      source: "GitHub/HN/Reddit",
      detail: `${chatterCount} public discussion lead${chatterCount === 1 ? "" : "s"} found across GitHub Issues/PRs, Hacker News, and Reddit.`,
      url: `https://github.com/search?q=${encodeURIComponent(cve)}&type=issues`
    });
  }

  const capped = Math.min(100, Math.round(score));
  const confirmed = Boolean(kev?.listed || vcFirst.reported_exploited_by_threat_actors || vcFirst.reported_exploited_by_ransomware);
  const publicExploitLevel = publicExploitSignals >= 10 ? "High" : publicExploitSignals > 0 ? "Present" : "Not observed";
  const chatterLevel = engagedChatter || chatterCount >= 20 ? "High" : chatterCount >= 5 ? "Moderate" : chatterCount > 0 ? "Low" : "None";
  const exploitedStatus = confirmed
    ? "Confirmed exploited in the wild"
    : vcFirst.weaponized_exploit_found || (epss?.epss >= 0.9 && publicExploitSignals > 0)
      ? "Strong exploitation signal"
      : publicExploitSignals > 0
        ? "Public exploit leads found"
        : "No public exploitation signal found";
  const verdict = confirmed || capped >= 70
    ? "Real-world issue"
    : capped >= 45
      ? "Likely real-world issue"
      : capped >= 20
        ? "Watch closely"
        : "Low current real-world signal";
  const confidence = confirmed || signals.length >= 4 ? "High" : signals.length >= 2 ? "Medium" : "Low";
  const summary = buildRealWorldSummary(verdict, exploitedStatus, chatterLevel, publicExploitLevel, {
    epss,
    kev,
    publicCodeCount,
    githubDiscussionCount,
    hackerNewsCount,
    redditCount
  });

  if (!signals.length) {
    signals.push({
      label: "No strong real-world signal",
      status: "Watch",
      source: "Public sources",
      detail: "No KEV listing, exploit reference, public code, or chatter signal was found from the configured sources.",
      url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`
    });
  }

  return {
    verdict,
    score: capped,
    confidence,
    exploitedStatus,
    chatterLevel,
    publicExploitLevel,
    summary,
    counts: {
      exploitReferences: exploitRefCount,
      publicCode: publicCodeCount,
      githubDiscussions: githubDiscussionCount,
      hackerNews: hackerNewsCount,
      reddit: redditCount,
      totalChatter: chatterCount,
      engagedChatter
    },
    signals
  };
}

function countEngagedChatter({ githubIssues, hackerNews, reddit }) {
  const githubEngaged = (githubIssues?.items || []).filter((item) => item.comments >= 5).length;
  const hnEngaged = (hackerNews?.items || []).filter((item) => item.comments >= 10 || item.points >= 25).length;
  const redditEngaged = (reddit?.items || []).filter((item) => item.comments >= 10 || item.score >= 25).length;
  return githubEngaged + hnEngaged + redditEngaged;
}

function buildRealWorldSummary(verdict, exploitedStatus, chatterLevel, publicExploitLevel, counts) {
  const parts = [`Verdict: ${verdict}. ${exploitedStatus}.`];
  if (counts.kev?.listed) {
    parts.push("CISA KEV is the strongest signal here because it means known exploitation has been confirmed by CISA.");
  }
  if (counts.epss?.epss !== null && counts.epss?.epss !== undefined) {
    parts.push(`EPSS is ${formatPercent(counts.epss.epss)}, which helps estimate exploitation probability but does not itself prove exploitation.`);
  }
  parts.push(`Public exploit level: ${publicExploitLevel}. Public chatter level: ${chatterLevel}.`);
  if (counts.publicCodeCount || counts.githubDiscussionCount || counts.hackerNewsCount || counts.redditCount) {
    parts.push(`Observed leads: ${counts.publicCodeCount} GitHub repository result${counts.publicCodeCount === 1 ? "" : "s"}, ${counts.githubDiscussionCount} GitHub discussion result${counts.githubDiscussionCount === 1 ? "" : "s"}, ${counts.hackerNewsCount} Hacker News result${counts.hackerNewsCount === 1 ? "" : "s"}, and ${counts.redditCount} Reddit result${counts.redditCount === 1 ? "" : "s"}.`);
  }
  return parts.join(" ");
}


function buildExploitMaturity(cve, { kev, github, references, vulncheck, evidence, epss }) {
  const vcRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const vcFirst = vcRows[0] || {};
  const refText = references.map((item) => `${item.url} ${item.title} ${(item.tags || []).join(" ")}`).join(" ").toLowerCase();
  const repoText = (github?.items || []).map((item) => `${item.name} ${item.description || ""}`).join(" ").toLowerCase();
  const publicCodeCount = github?.totalCount || 0;
  const exploitRefs = references.filter((item) => item.type === "exploit").length;
  const scannerModule = /metasploit|nuclei|scanner|module|template|exploit-db|packetstorm/.test(`${refText} ${repoText}`);
  let stage = "No exploit found";
  let score = 10;
  const signals = [];

  if (kev?.listed || vcFirst.reported_exploited_by_threat_actors || vcFirst.reported_exploited_by_ransomware) {
    stage = "Weaponized or in-the-wild";
    score = 95;
    signals.push("Known exploitation is confirmed by CISA KEV or commercial intelligence.");
  } else if (vcFirst.weaponized_exploit_found) {
    stage = "Weaponized or in-the-wild";
    score = 90;
    signals.push("Commercial exploit intelligence reports weaponized exploit maturity.");
  } else if (scannerModule) {
    stage = "Scanner/module available";
    score = 78;
    signals.push("Public references suggest Metasploit, Nuclei, scanner, module, or template coverage.");
  } else if (exploitRefs > 0 || publicCodeCount > 0 || vcFirst.public_exploit_found || vcFirst.commercial_exploit_found) {
    stage = "Public PoC available";
    score = 62;
    signals.push("Exploit references or public code leads were found.");
  } else if (epss?.epss >= 0.5) {
    stage = "PoC suspected";
    score = 44;
    signals.push("EPSS is elevated even though public exploit evidence is limited.");
  }

  if (exploitRefs) signals.push(`${exploitRefs} exploit-tagged reference${exploitRefs === 1 ? "" : "s"}.`);
  if (publicCodeCount) signals.push(`${publicCodeCount} GitHub repository lead${publicCodeCount === 1 ? "" : "s"}.`);
  if (!signals.length) signals.push("No strong exploit maturity signal found from configured sources.");

  return { stage, score, scannerModule, exploitRefs, publicCodeCount, signals };
}

function buildVendorPatchIntelligence(cve, { affected, references, remediation }) {
  const patchRefs = references.filter((item) => item.type === "patch");
  const mitigationRefs = references.filter((item) => item.type === "mitigation");
  const advisoryRefs = references.filter((item) => item.type === "advisory");
  const fixedVersionSignals = [];
  for (const item of affected) {
    const text = `${item.version || ""}`;
    if (/unaffected|fixed|lessThan|<=|>=|</i.test(text)) {
      fixedVersionSignals.push(`${item.vendor} ${item.product}: ${text}`);
    }
  }
  return {
    status: patchRefs.length || advisoryRefs.length ? "Vendor guidance found" : "Needs manual vendor review",
    affectedProducts: affected.slice(0, 12),
    fixedVersionSignals: [...new Set(fixedVersionSignals)].slice(0, 10),
    patchRefs: patchRefs.slice(0, 8),
    mitigationRefs: mitigationRefs.slice(0, 8),
    advisoryRefs: advisoryRefs.slice(0, 10),
    primaryLinks: remediation.primaryLinks || [],
    summary: `${affected.length} affected product signal${affected.length === 1 ? "" : "s"}, ${advisoryRefs.length} advisory reference${advisoryRefs.length === 1 ? "" : "s"}, ${patchRefs.length} patch reference${patchRefs.length === 1 ? "" : "s"}.`
  };
}

function buildCloudImpact(cve, { title, description, affected, references, kev }) {
  const officialRefs = references
    .filter((reference) => isAwsOfficialReference(reference.url) || isAzureOfficialReference(reference.url))
    .map((reference) => ({
      provider: isAwsOfficialReference(reference.url) ? "AWS" : "Azure",
      label: readableLinkLabel(reference),
      url: reference.url,
      source: reference.source || "Reference"
    }));
  const searchLinks = buildCloudImpactLinks(cve);
  const evidenceText = normalizeCloudText([
    title,
    description,
    kev?.vendorProject,
    kev?.product,
    kev?.vulnerabilityName,
    ...(affected || []).flatMap((item) => [item.vendor, item.product, item.version, item.cpe, item.source]),
    ...(references || []).flatMap((item) => [item.url, item.title, item.source, ...(item.tags || [])])
  ].filter(Boolean).join(" "));
  const affectedText = normalizeCloudText((affected || []).map((item) => `${item.vendor} ${item.product} ${item.version}`).join(" "));
  const services = [];

  for (const rule of cloudServiceCatalog) {
    const matchedKeywords = rule.keywords.filter((keyword) => cloudTextHas(evidenceText, keyword));
    const directProviderSignal = rule.provider === "AWS" ? hasAwsSignal(affectedText, officialRefs) : hasAzureSignal(affectedText, officialRefs);
    if (!matchedKeywords.length && !directProviderSignal) continue;

    services.push({
      provider: rule.provider,
      service: rule.service,
      status: directProviderSignal && matchedKeywords.length ? "Affected or explicitly referenced" : "Might be affected",
      confidence: directProviderSignal && matchedKeywords.length ? "High" : matchedKeywords.length >= 2 ? "Medium" : "Low",
      reason: matchedKeywords.length
        ? `Matched ${matchedKeywords.slice(0, 4).join(", ")} in CVE metadata, affected products, or references.`
        : `Official ${rule.provider} signal found; verify whether this service is included in the provider advisory.`,
      action: rule.action,
      links: [
        { label: `${rule.service} guidance`, url: rule.url },
        ...officialRefs.filter((item) => item.provider === rule.provider).slice(0, 2),
        ...searchLinks.filter((item) => item.provider === rule.provider).slice(0, 2)
      ]
    });
  }

  const servicesByProvider = {
    AWS: services.filter((item) => item.provider === "AWS"),
    Azure: services.filter((item) => item.provider === "Azure")
  };
  const providers = ["AWS", "Azure"].map((provider) => {
    const providerRefs = officialRefs.filter((item) => item.provider === provider);
    const providerServices = servicesByProvider[provider] || [];
    return {
      provider,
      status: providerRefs.length
        ? `Official ${provider === "AWS" ? "AWS" : "Microsoft/Azure"} advisory reference found`
        : providerServices.length
          ? "Possible customer-managed cloud exposure"
          : "No cloud-specific signal found",
      confidence: providerRefs.length ? "High" : providerServices.length ? "Medium" : "Low",
      serviceCount: providerServices.length,
      officialReferenceCount: providerRefs.length,
      guidance: providerRefs.length
        ? "Review the official cloud advisory first, then validate whether your account, region, service version, images, or workloads require action."
        : providerServices.length
          ? "No official cloud advisory was found in the CVE references, but the affected product commonly appears in customer-managed cloud workloads."
          : "No AWS or Azure service match was inferred. Still check cloud inventory if you run the affected product yourself.",
      links: [
        ...providerRefs,
        ...searchLinks.filter((item) => item.provider === provider)
      ].slice(0, 6)
    };
  });
  const summary = buildCloudImpactSummary(providers, services);
  return {
    summary,
    providers,
    services: services.slice(0, 30),
    links: searchLinks,
    officialRefs,
    plainText: buildCloudImpactPlainText(cve, { summary, providers, services, officialRefs, searchLinks })
  };
}

function buildCloudImpactSummary(providers, services) {
  const official = providers.filter((item) => item.officialReferenceCount > 0).map((item) => item.provider);
  const possible = providers.filter((item) => !item.officialReferenceCount && item.serviceCount > 0).map((item) => item.provider);
  if (official.length) {
    return `${official.join(" and ")} official advisory signal found. ${services.length} cloud service candidate${services.length === 1 ? "" : "s"} should be validated.`;
  }
  if (possible.length) {
    return `${possible.join(" and ")} may have customer-managed workload exposure. ${services.length} cloud service candidate${services.length === 1 ? "" : "s"} matched affected product signals.`;
  }
  return "No AWS or Azure service-specific signal was inferred from the configured sources.";
}

function buildCloudImpactPlainText(cve, { summary, providers, services, officialRefs, searchLinks }) {
  const lines = [
    `Cloud impact review for ${cve}`,
    summary,
    "",
    "Provider status:"
  ];
  for (const provider of providers) {
    lines.push(`- ${provider.provider}: ${provider.status} (${provider.confidence} confidence). ${provider.guidance}`);
  }
  lines.push("");
  lines.push("Cloud services to validate:");
  if (services.length) {
    for (const item of services.slice(0, 16)) {
      lines.push(`- ${item.provider} - ${item.service}: ${item.status} (${item.confidence}). ${item.action}`);
      lines.push(`  Reason: ${item.reason}`);
    }
  } else {
    lines.push("- No service-specific match found. Check AWS and Azure inventory manually if this product is deployed in cloud workloads.");
  }
  lines.push("");
  lines.push("Official cloud references found in CVE data:");
  if (officialRefs.length) {
    for (const ref of officialRefs.slice(0, 10)) lines.push(`- ${ref.provider}: ${ref.label}: ${ref.url}`);
  } else {
    lines.push("- None found in NVD/CVE/CISA references.");
  }
  lines.push("");
  lines.push("Cloud research links:");
  for (const link of searchLinks) lines.push(`- ${link.label}: ${link.url}`);
  return lines.join("\n");
}

function buildCloudImpactLinks(cve) {
  const encoded = encodeURIComponent(cve);
  return [
    { provider: "AWS", label: "AWS Security Bulletins", url: "https://aws.amazon.com/security/security-bulletins/" },
    { provider: "AWS", label: "AWS site search for this CVE", url: `https://aws.amazon.com/search/?searchQuery=${encoded}` },
    { provider: "AWS", label: "Amazon Linux Security Center", url: "https://alas.aws.amazon.com/" },
    { provider: "Azure", label: "Microsoft Security Update Guide", url: `https://msrc.microsoft.com/update-guide/vulnerability/${encoded}` },
    { provider: "Azure", label: "MSRC Update Guide search", url: `https://msrc.microsoft.com/update-guide?search=${encoded}` },
    { provider: "Azure", label: "Azure Updates search", url: `https://azure.microsoft.com/updates/?query=${encoded}` }
  ];
}

function isAwsOfficialReference(url = "") {
  const value = String(url).toLowerCase();
  return /aws\.amazon\.com\/security\/security-bulletins|alas\.aws\.amazon\.com|docs\.aws\.amazon\.com|github\.com\/bottlerocket-os|github\.com\/aws\//.test(value);
}

function isAzureOfficialReference(url = "") {
  const value = String(url).toLowerCase();
  return /msrc\.microsoft\.com|portal\.msrc\.microsoft\.com|azure\.microsoft\.com|learn\.microsoft\.com\/azure|github\.com\/azure|github\.com\/microsoft/.test(value);
}

function hasAwsSignal(text, officialRefs) {
  return /amazon web services|amazon linux|aws|bottlerocket|amazon ecs|amazon eks|aws fargate|amazon ec2/.test(text) || officialRefs.some((item) => item.provider === "AWS");
}

function hasAzureSignal(text, officialRefs) {
  return /azure|microsoft|windows|defender|aks|app service|azure linux|cbl-mariner/.test(text) || officialRefs.some((item) => item.provider === "Azure");
}

function normalizeCloudText(value) {
  return String(value || "").toLowerCase().replace(/[_-]/g, " ").replace(/\s+/g, " ");
}

function cloudTextHas(text, keyword) {
  return text.includes(normalizeCloudText(keyword));
}

function buildDetectionGuidance(cve, { title, cvss, kev, weaknesses, realWorld, exploitMaturity, references }) {
  const weaknessText = weaknesses.map((item) => item.id).join(", ") || "no CWE extracted";
  const checks = [
    "Review vulnerability scanner results and confirm authenticated plugin coverage for every affected host.",
    "Search EDR/SIEM logs for exploit attempts, new child processes from exposed services, suspicious file writes, newly created users, and unusual outbound network connections.",
    "Review WAF, reverse proxy, load balancer, and web server logs for requests matching vendor advisories, public PoC paths, payload markers, or abnormal error spikes.",
    "Confirm compensating controls: network segmentation, external exposure reduction, WAF rules, EDR prevention, and least-privilege service accounts.",
    "After remediation, rescan and preserve evidence of fixed versions, mitigation settings, or accepted-risk approval."
  ];
  if (kev?.listed) checks.unshift("Treat this as an active exploitation monitoring item because CISA KEV lists known exploitation.");
  if (/remote|rce|code execution|command/i.test(`${title} ${weaknessText}`)) {
    checks.splice(1, 0, "For possible RCE, look for shell execution, scripting engine launches, unexpected service restarts, web shells, dropped binaries, and privilege escalation activity.");
  }
  const lines = [
    `Detection and validation guidance for ${cve}`,
    `Title: ${title}`,
    `Severity: ${cvss?.score ? `${cvss.severity || "Unknown"} / CVSS ${cvss.score}` : "Unknown"}`,
    `Real-world signal: ${realWorld?.verdict || "Unknown"}; exploit maturity: ${exploitMaturity?.stage || "Unknown"}`,
    `Weakness signals: ${weaknessText}`,
    "",
    "Monitoring and validation checklist:",
    ...checks.map((item, index) => `${index + 1}. ${item}`),
    "",
    "Reference links:",
    `- NVD: https://nvd.nist.gov/vuln/detail/${cve}`,
    `- CVE.org: https://www.cve.org/CVERecord?id=${cve}`,
    ...references.slice(0, 5).map((item) => `- ${readableLinkLabel(item)}: ${item.url}`)
  ];
  return { checks, plainText: lines.join("\n") };
}

function buildExecutiveBrief(cve, { title, risk, realWorld, exploitMaturity, vendorPatch, cloudImpact, remediation, affected }) {
  const lines = [
    `Executive summary for ${cve}`,
    `Title: ${title}`,
    `Business urgency: ${risk.level} (${risk.score}/100).`,
    `Real-world verdict: ${realWorld?.verdict || "Unknown"}. ${realWorld?.exploitedStatus || ""}`.trim(),
    `Exploit maturity: ${exploitMaturity?.stage || "Unknown"}.`,
    `Patch status: ${vendorPatch?.status || "Unknown"}.`,
    `Cloud impact: ${cloudImpact?.summary || "Not assessed."}`,
    `Potential exposure: ${affected.length} affected product signal${affected.length === 1 ? "" : "s"} found.`,
    "",
    "Recommended decision:",
    risk.score >= 80 ? "Treat as urgent remediation. Prioritize internet-facing and business-critical assets first." : "Validate exposure and remediate according to normal vulnerability SLA unless exposed assets are found.",
    "",
    "Primary links:",
    ...(remediation.primaryLinks || []).slice(0, 6).map((item) => `- ${item.label}: ${item.url}`)
  ];
  return { plainText: lines.join("\n") };
}

function buildTicketExport(cve, { title, risk, realWorld, exploitMaturity, vendorPatch, cloudImpact, remediation, affected, detectionGuidance }) {
  const lines = [
    `[${risk.level}] Remediate ${cve} - ${title}`,
    "",
    "Summary:",
    `${cve} requires review and remediation. Real-world verdict: ${realWorld?.verdict || "Unknown"}. Exploit maturity: ${exploitMaturity?.stage || "Unknown"}.`,
    "",
    "Business impact:",
    risk.score >= 80 ? "Potential high business impact if affected systems are exposed or unpatched. Prioritize production and internet-facing assets." : "Business impact depends on whether affected products are present in the environment.",
    "",
    "Scope to validate:",
    ...(affected.slice(0, 8).map((item) => `- ${item.vendor} ${item.product}: ${item.version || item.cpe || "see advisory"}`) || []),
    "",
    "Cloud impact:",
    cloudImpact?.summary || "Cloud impact was not assessed.",
    ...(cloudImpact?.services || []).slice(0, 8).map((item) => `- ${item.provider} ${item.service}: ${item.status}. ${item.action}`),
    "",
    "Remediation steps:",
    remediation.plainText || "Review vendor advisory, patch or mitigate, then validate with scanner evidence.",
    "",
    "Detection / validation:",
    ...(detectionGuidance.checks || []).map((item) => `- ${item}`),
    "",
    "Links:",
    ...(vendorPatch.primaryLinks || remediation.primaryLinks || []).slice(0, 10).map((item) => `- ${item.label}: ${item.url}`)
  ];
  return { plainText: lines.join("\n") };
}

function buildRiskAcceptanceNote(cve, { title, risk, realWorld, exploitMaturity, remediation, detectionGuidance }) {
  const lines = [
    `Risk acceptance note for ${cve}`,
    "",
    `Vulnerability: ${title}`,
    `Risk level: ${risk.level} (${risk.score}/100)` ,
    `Real-world verdict: ${realWorld?.verdict || "Unknown"}`,
    `Exploit maturity: ${exploitMaturity?.stage || "Unknown"}`,
    "",
    "Reason patching is deferred:",
    "[Enter business or technical reason here.]",
    "",
    "Temporary controls required until remediation:",
    "- Restrict network exposure and remove unnecessary internet access.",
    "- Apply vendor-approved mitigation or compensating control where available.",
    "- Increase monitoring using the detection checklist below.",
    "- Set an expiration date and named owner for this exception.",
    "",
    "Monitoring commitments:",
    ...(detectionGuidance.checks || []).slice(0, 5).map((item) => `- ${item}`),
    "",
    "Remediation target:",
    remediation.steps?.find((step) => step.dueDate)?.dueDate ? `Complete by ${remediation.steps.find((step) => step.dueDate).dueDate}.` : "Set target date: [enter date].",
    "",
    "Approval:",
    "System owner: [name]",
    "Security approver: [name]",
    "Expiration date: [date]"
  ];
  return { plainText: lines.join("\n") };
}

function calculateRisk({ cvss, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, evidence }) {
  let score = 0;
  const reasons = [];

  if (cvss?.score >= 9) {
    score += 25;
    reasons.push("critical CVSS");
  } else if (cvss?.score >= 7) {
    score += 18;
    reasons.push("high CVSS");
  } else if (cvss?.score >= 4) {
    score += 9;
    reasons.push("medium CVSS");
  }

  if (epss?.epss >= 0.9) {
    score += 24;
    reasons.push("very high EPSS");
  } else if (epss?.epss >= 0.5) {
    score += 18;
    reasons.push("high EPSS");
  } else if (epss?.epss >= 0.1) {
    score += 10;
    reasons.push("notable EPSS");
  }

  if (kev?.listed) {
    score += 35;
    reasons.push("CISA KEV");
  }
  if (kev?.knownRansomwareCampaignUse === "Known") {
    score += 18;
    reasons.push("known ransomware use");
  }

  const githubCount = github?.totalCount || 0;
  if (githubCount > 25) {
    score += 15;
    reasons.push("many public code hits");
  } else if (githubCount > 0) {
    score += 8;
    reasons.push("public code hits");
  }

  const vcRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const vcFirst = vcRows[0] || {};
  if (vcFirst.weaponized_exploit_found) {
    score += 25;
    reasons.push("weaponized exploit");
  } else if (vcFirst.public_exploit_found || vcFirst.commercial_exploit_found) {
    score += 14;
    reasons.push("exploit available");
  }
  if (vcFirst.reported_exploited_by_ransomware) {
    score += 18;
    reasons.push("ransomware reporting");
  }

  const exploitEvidence = evidence.filter((item) => /exploit|public-code|commercial/.test(item.type)).length;
  if (exploitEvidence >= 5) {
    score += 6;
    reasons.push("multiple exploit references");
  }

  const chatterCount = (githubIssues?.totalCount || 0) + (hackerNews?.totalCount || 0) + (reddit?.totalCount || 0);
  if (chatterCount > 25) {
    score += 8;
    reasons.push("high public discussion");
  } else if (chatterCount > 0) {
    score += 3;
    reasons.push("public discussion");
  }

  const capped = Math.min(100, Math.round(score));
  return {
    score: capped,
    level: riskLevel(capped),
    reasons
  };
}

function riskLevel(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 35) return "Elevated";
  return "Watch";
}

function calculateConfidence(sourceResults, nvd, cveOrg) {
  const ok = sourceResults.filter((source) => source.status === "ok").length;
  let score = ok * 12;
  if (nvd) score += 18;
  if (cveOrg) score += 18;
  const capped = Math.min(100, score);
  return {
    score: capped,
    label: capped >= 75 ? "High" : capped >= 45 ? "Medium" : "Low"
  };
}

function buildExecutiveSummary(cve, title, description, { cvss, epss, kev, github, githubIssues, hackerNews, reddit, vulncheck, affected, risk, realWorld, cloudImpact }) {
  const parts = [];
  parts.push(`${cve}: ${title}`);
  if (description) parts.push(sentence(description));
  if (realWorld) {
    parts.push(`Real-world verdict: ${realWorld.verdict}. ${realWorld.exploitedStatus}.`);
  }
  if (cvss?.score) parts.push(`Severity is ${cvss.severity || "unknown"} with CVSS ${cvss.score}.`);
  if (epss?.epss !== null && epss?.epss !== undefined) {
    parts.push(`EPSS estimates ${formatPercent(epss.epss)} exploitation probability, percentile ${formatPercent(epss.percentile)}.`);
  }
  if (kev?.listed) {
    parts.push(`CISA KEV confirms known exploitation${kev.knownRansomwareCampaignUse === "Known" ? " with known ransomware use" : ""}.`);
  } else if (kev) {
    parts.push("CISA KEV did not list this CVE in the current catalog response.");
  }
  const vcRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const vcFirst = vcRows[0] || {};
  if (vcFirst.max_exploit_maturity) {
    parts.push(`VulnCheck max exploit maturity is ${vcFirst.max_exploit_maturity}.`);
  }
  if (github?.totalCount) {
    parts.push(`GitHub repository search found ${github.totalCount} matching public result${github.totalCount === 1 ? "" : "s"}; treat these as leads until manually validated.`);
  }
  const chatterCount = (githubIssues?.totalCount || 0) + (hackerNews?.totalCount || 0) + (reddit?.totalCount || 0);
  if (chatterCount) {
    parts.push(`Public chatter search found ${chatterCount} discussion lead${chatterCount === 1 ? "" : "s"} across GitHub Issues/PRs, Hacker News, and Reddit.`);
  }
  if (affected.length) {
    const first = affected[0];
    parts.push(`Initial affected product signal includes ${first.vendor} ${first.product}.`);
  }
  if (cloudImpact?.summary) {
    parts.push(`Cloud impact: ${cloudImpact.summary}`);
  }
  parts.push(`Overall triage level: ${risk.level} (${risk.score}/100).`);
  return parts.join(" ");
}

function buildAnalystActions({ cve, risk, realWorld, kev, epss, github, githubIssues, hackerNews, reddit, vulncheck, affected, references, cloudImpact }) {
  const actions = [
    {
      id: "real-world",
      label: "Decide whether this is a real-world incident driver",
      priority: realWorld?.verdict === "Real-world issue" ? "Critical" : realWorld?.verdict === "Likely real-world issue" ? "High" : "Medium",
      detail: realWorld ? `${realWorld.verdict}: ${realWorld.exploitedStatus}. Chatter level: ${realWorld.chatterLevel}.` : "Real-world assessment was not available."
    },
    {
      id: "inventory",
      label: "Match affected product indicators against asset inventory",
      priority: affected.length ? "High" : "Medium",
      detail: affected.length ? `${affected.length} affected indicator${affected.length === 1 ? "" : "s"} available.` : "No affected product list was extracted."
    },
    {
      id: "cloud-impact",
      label: "Check AWS and Azure exposure",
      priority: cloudImpact?.officialRefs?.length ? "High" : cloudImpact?.services?.length ? "Medium" : "Low",
      detail: cloudImpact?.summary || "No AWS or Azure service-specific signal was inferred."
    },
    {
      id: "patch",
      label: "Confirm vendor fixed versions and remediation path",
      priority: references.some((item) => item.type === "patch") || kev?.listed ? "High" : "Medium",
      detail: `${references.filter((item) => item.type === "patch" || item.type === "advisory").length} patch/advisory reference${references.length === 1 ? "" : "s"} found.`
    },
    {
      id: "exploit",
      label: "Validate exploitability evidence before escalating",
      priority: risk.score >= 60 ? "High" : "Medium",
      detail: github?.totalCount ? `${github.totalCount} GitHub lead${github.totalCount === 1 ? "" : "s"} found.` : "No public GitHub repository lead returned."
    },
    {
      id: "chatter",
      label: "Review public chatter for operational details",
      priority: realWorld?.chatterLevel === "High" ? "High" : "Medium",
      detail: `${(githubIssues?.totalCount || 0) + (hackerNews?.totalCount || 0) + (reddit?.totalCount || 0)} public discussion lead${(githubIssues?.totalCount || 0) + (hackerNews?.totalCount || 0) + (reddit?.totalCount || 0) === 1 ? "" : "s"} found across GitHub Issues/PRs, Hacker News, and Reddit.`
    },
    {
      id: "detections",
      label: "Check scanner plugins, SIEM detections, and edge telemetry",
      priority: kev?.listed || epss?.epss >= 0.5 ? "High" : "Medium",
      detail: kev?.listed ? "Known exploited vulnerabilities should get accelerated detection review." : `Use source links for ${cve} to inspect external telemetry.`
    }
  ];

  const vcRows = Array.isArray(vulncheck?.exploits) ? vulncheck.exploits : [];
  const vcFirst = vcRows[0] || {};
  if (vcFirst.weaponized_exploit_found) {
    actions.unshift({
      id: "weaponized",
      label: "Escalate as weaponized exploit intelligence",
      priority: "Critical",
      detail: "Optional VulnCheck data reports a weaponized exploit signal."
    });
  }
  return actions;
}

function buildSourceLinks(cve) {
  const encoded = encodeURIComponent(cve);
  return [
    { label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${encoded}` },
    { label: "CVE.org", url: `https://www.cve.org/CVERecord?id=${encoded}` },
    { label: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
    { label: "AWS Security Bulletins", url: "https://aws.amazon.com/security/security-bulletins/" },
    { label: "AWS CVE Search", url: `https://aws.amazon.com/search/?searchQuery=${encoded}` },
    { label: "Microsoft Security Update Guide", url: `https://msrc.microsoft.com/update-guide/vulnerability/${encoded}` },
    { label: "Azure Updates Search", url: `https://azure.microsoft.com/updates/?query=${encoded}` },
    { label: "FIRST EPSS", url: `https://api.first.org/data/v1/epss?cve=${encoded}` },
    { label: "GitHub Search", url: `https://github.com/search?q=${encoded}&type=repositories` },
    { label: "GitHub Issues/PRs", url: `https://github.com/search?q=${encoded}&type=issues` },
    { label: "GitHub Advisory Database", url: `https://github.com/advisories?query=${encoded}` },
    { label: "Hacker News", url: `https://hn.algolia.com/?q=${encoded}` },
    { label: "Reddit Search", url: `https://www.reddit.com/search/?q=${encoded}` },
    { label: "Exploit-DB Search", url: `https://www.exploit-db.com/search?cve=${encoded.replace("CVE-", "")}` },
    { label: "Vulners Search", url: `https://vulners.com/search?query=${encoded}` },
    { label: "VulnCheck XDB", url: `https://www.vulncheck.com/xdb?q=${encoded}` },
    { label: "GreyNoise Search", url: `https://viz.greynoise.io/query?gnql=${encoded}` },
    { label: "Google News", url: `https://www.google.com/search?q=${encoded}+vulnerability+exploit+analysis` }
  ];
}

function buildRemediationRefs(references) {
  return references.filter((item) => ["patch", "advisory", "mitigation"].includes(item.type));
}

function summarizeKev(kev) {
  if (!kev?.listed) {
    return {
      listed: false,
      catalogVersion: kev?.catalogVersion || null,
      dateReleased: kev?.dateReleased || null
    };
  }
  return {
    listed: true,
    vendorProject: kev.vendorProject,
    product: kev.product,
    vulnerabilityName: kev.vulnerabilityName,
    dateAdded: kev.dateAdded,
    dueDate: kev.dueDate,
    requiredAction: kev.requiredAction,
    knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse
  };
}

function summarizeGithub(github) {
  return {
    totalCount: github.totalCount || 0,
    incomplete: Boolean(github.incomplete),
    topRepos: (github.items || []).slice(0, 5)
  };
}

function summarizeGithubIssues(githubIssues) {
  return {
    totalCount: githubIssues.totalCount || 0,
    incomplete: Boolean(githubIssues.incomplete),
    topItems: (githubIssues.items || []).slice(0, 5)
  };
}

function summarizeGithubAdvisories(githubAdvisories) {
  return {
    totalCount: githubAdvisories?.totalCount || 0,
    reviewed: (githubAdvisories?.items || []).filter((item) => !item.withdrawnAt).length,
    withdrawn: (githubAdvisories?.items || []).filter((item) => item.withdrawnAt).length,
    packages: (githubAdvisories?.items || []).reduce((count, item) => count + (item.vulnerabilities?.length || 0), 0)
  };
}

function summarizeHackerNews(hackerNews) {
  return {
    totalCount: hackerNews.totalCount || 0,
    topItems: (hackerNews.items || []).slice(0, 5)
  };
}

function summarizeReddit(reddit) {
  return {
    totalCount: reddit.totalCount || 0,
    topItems: (reddit.items || []).slice(0, 5)
  };
}

function severityFromScore(score) {
  const value = Number(score);
  if (value >= 9) return "CRITICAL";
  if (value >= 7) return "HIGH";
  if (value >= 4) return "MEDIUM";
  if (value > 0) return "LOW";
  return "UNKNOWN";
}

function sentence(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  const match = text.match(/^(.+?[.!?])(\s|$)/);
  return (match?.[1] || text).slice(0, 420);
}

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "n/a";
  return `${(Number(value) * 100).toFixed(Number(value) < 0.01 ? 3 : 1)}%`;
}

function hash(value) {
  let h = 0;
  const str = String(value || "");
  for (let i = 0; i < str.length; i += 1) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36);
}

function jsonApiResponse(body, statusCode = 200, extraHeaders = {}) {
  return {
    statusCode,
    headers: withSecurityHeaders({
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }),
    body: JSON.stringify(body, null, 2)
  };
}

function genericServerErrorBody() {
  return {
    error: true,
    message: "The research server hit an unexpected error."
  };
}

function writeApiResponse(res, response) {
  res.writeHead(response.statusCode || 200, response.headers || {});
  res.end(response.body || "");
}

function sendJson(res, body, statusCode = 200, extraHeaders = {}) {
  res.writeHead(statusCode, withSecurityHeaders({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders
  }));
  res.end(JSON.stringify(body, null, 2));
}

function sendText(res, body, statusCode = 200, extraHeaders = {}) {
  res.writeHead(statusCode, withSecurityHeaders({
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders
  }));
  res.end(body);
}
