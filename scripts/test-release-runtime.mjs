import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const directory = await mkdtemp(join(tmpdir(), "vulnscope-bundle-test-"));
try {
  const manifest = JSON.parse(await readFile(".deploy/release/release.json", "utf8"));
  execFileSync("python3", ["scripts/verify-bundle.py", ".deploy/deployment.tar.gz", directory, manifest.sourceDigest, manifest.sourceRef, ...(process.env.ALLOW_DIRTY_BUNDLE === "1" ? ["--allow-dirty"] : [])], { stdio: "inherit" });
  const release = join(directory, "release");
  const html = await readFile(join(release, "public/index.html"), "utf8");
  assert(html.includes('/generated/app.js'));
  const bundle = await readFile(join(release, "public/generated/app.js"), "utf8");
  assert(bundle.length > 10000);
  const runtime = join(directory, "runtime");
  execFileSync("unzip", ["-q", join(release, "lambda.zip"), "-d", runtime]);
  process.env.MOCK_RESEARCH = "1";
  delete process.env.ORIGIN_VERIFY_SECRET;
  delete process.env.AWS_LAMBDA_FUNCTION_NAME;
  const { handler } = await import(pathToFileURL(resolve(runtime, "lambda.mjs")));
  const response = await handler({ version: "2.0", rawPath: "/api/research", rawQueryString: "cve=CVE-2024-0001", headers: {}, requestContext: { http: { method: "GET", sourceIp: "127.0.0.1" } } });
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(response.body).id, "CVE-2024-0001");
  console.log(`PASS actual archive manifest, frontend entry, extracted Lambda imports and offline API fixture (${manifest.sourceDigest}; dirty=${manifest.dirty})`);
} finally { await rm(directory, { recursive: true, force: true }); }
