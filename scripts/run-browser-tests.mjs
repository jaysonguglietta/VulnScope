import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { appRequestHandler } from "../server.mjs";

const server = createServer(appRequestHandler);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
try {
  for (const script of ["scripts/browser-security-smoke.mjs", "scripts/browser-product-smoke.mjs"]) {
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [script], { stdio: "inherit", env: { ...process.env, TEST_BASE_URL: base } });
      child.on("error", reject);
      child.on("exit", (code) => code === 0 ? resolve() : reject(new Error(`${script} failed (${code})`)));
    });
  }
} finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
