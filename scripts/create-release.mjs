import { cp, mkdir, readdir, readFile, lstat, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { resolve, join } from "node:path";

function run(command, args, cwd = process.cwd(), env = {}) {
  const result = spawnSync(command, args, { cwd, env: { ...process.env, ...env }, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  if (result.status !== 0) throw new Error(command + " failed");
  return result.stdout.trim();
}

const root = process.cwd();
const output = resolve(".deploy");
await mkdir(output, { recursive: true });
const staging = join(output, "release");
const lambda = join(output, "lambda");
await rm(staging, { recursive: true, force: true });
await rm(lambda, { recursive: true, force: true });
await mkdir(lambda, { recursive: true });
await mkdir(staging, { recursive: true });
for (const file of ["server.mjs", "lambda.mjs", "monitor.mjs", "package.json", "package-lock.json"]) await cp(file, join(lambda, file));
await safeCopy(join(root, "lib"), join(lambda, "lib"));
await mkdir(join(lambda, "public/modules"), { recursive: true });
await safeCopy(join(root, "public/modules/research-model.js"), join(lambda, "public/modules/research-model.js"));
run("npm", ["ci", "--omit=dev", "--ignore-scripts"], lambda);
run("zip", ["-qr", join(staging, "lambda.zip"), "."], lambda);

async function safeCopy(source, target) {
  const stat = await lstat(source);
  if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) throw new Error("Release refuses links/special files: " + source);
  if (stat.isDirectory()) {
    await mkdir(target, { recursive: true });
    for (const name of (await readdir(source)).sort()) await safeCopy(join(source, name), join(target, name));
  } else await cp(source, target);
}
await safeCopy(join(root, "public"), join(staging, "public"));
await safeCopy(join(root, "infra"), join(staging, "infra"));
await lstat(join(staging, "public/generated/sbom-worker.js"));
await lstat(join(staging, "public/generated/app.js"));
const files = {};
async function inventory(directory, prefix = "") {
  for (const name of (await readdir(directory)).sort()) {
    const path = join(directory, name), relative = prefix + name;
    if ((await lstat(path)).isDirectory()) await inventory(path, relative + "/");
    else files[relative] = createHash("sha256").update(await readFile(path)).digest("hex");
  }
}
await inventory(staging);
const sourceDigest = process.env.GITHUB_SHA || run("git", ["rev-parse", "HEAD"]);
const sourceRef = process.env.GITHUB_REF || run("git", ["symbolic-ref", "HEAD"]);
const dirty = Boolean(run("git", ["status", "--porcelain"]));
if (process.env.GITHUB_ACTIONS === "true" && dirty) throw new Error("CI release requires a clean source checkout.");
await writeFile(join(staging, "release.json"), JSON.stringify({ schemaVersion: 1, sourceDigest, sourceRef, dirty, files }, null, 2) + "\n");
// macOS resource forks are not release payloads or manifest entries.
run("tar", ["-czf", join(output, "deployment.tar.gz"), "release"], output, { COPYFILE_DISABLE: "1" });
const digest = createHash("sha256").update(await readFile(join(output, "deployment.tar.gz"))).digest("hex");
await writeFile(join(output, "deployment.tar.gz.sha256"), digest + "  deployment.tar.gz\n");
console.log("Created .deploy/deployment.tar.gz (" + sourceDigest + ")");
