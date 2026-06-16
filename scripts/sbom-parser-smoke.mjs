import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

class FakeElement {
  constructor() {
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.dataset = {};
    this.files = [];
    this.content = { cloneNode: () => ({}) };
  }
  addEventListener() {}
  setAttribute() {}
  removeAttribute() {}
  replaceChildren() {}
  focus() {}
}

const fakeElement = new FakeElement();
globalThis.document = {
  querySelector: () => fakeElement,
  querySelectorAll: () => [],
  addEventListener: () => {},
  createElement: () => fakeElement,
  body: { append: () => {} }
};
globalThis.window = {
  confirm: () => true
};
globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: {
    clipboard: {
      writeText: async () => {}
    }
  }
});
globalThis.requestAnimationFrame = (callback) => callback();
globalThis.fetch = async () => ({
  json: async () => ({ sources: [] })
});

const appSource = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const sample = readFileSync(new URL("fixtures/sample-cyclonedx.json", import.meta.url), "utf8");
const testSource = `${appSource}

function smokeAssert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const sampleText = ${JSON.stringify(sample)};
const parsed = parseSbomFile({ name: "sample-cyclonedx.json", size: sampleText.length }, sampleText);
const report = buildSbomReport([parsed], []);
smokeAssert(parsed.format === "CycloneDX 1.5", "expected CycloneDX parser");
smokeAssert(report.components.length === 1, "expected one component");
smokeAssert(report.cves.some((entry) => entry.id === "CVE-2021-44228"), "expected Log4Shell CVE");
smokeAssert(report.vulnerabilities.some((entry) => entry.components.some((component) => component.includes("log4j-core"))), "expected affected component mapping");
`;

const tempDir = mkdtempSync(join(tmpdir(), "vulnscope-sbom-test-"));
const tempModule = join(tempDir, "sbom-parser-test.mjs");
writeFileSync(tempModule, testSource);
await import(pathToFileURL(tempModule).href);
console.log("sbom parser smoke test passed");
