import { XMLParser, XMLValidator } from "fast-xml-parser";
import { assertSbomStructure } from "./sbom-budget.js";

export function xmlToCycloneDx(text) {
  if (/<!\s*(?:DOCTYPE|ENTITY)/i.test(text)) throw new Error("XML DTDs and entity declarations are not accepted.");
  if (XMLValidator.validate(text) !== true) throw new Error("Invalid XML.");
  let tags = 0;
  const xml = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: "", removeNSPrefix: true,
    parseTagValue: false, parseAttributeValue: false, maxNestedTags: 40,
    processEntities: { enabled: true, maxExpansionDepth: 1, maxEntityCount: 5, maxTotalExpansions: 20000, maxExpandedLength: 8192 },
    updateTag(name) { if (++tags > 20000) throw new Error("XML tag limit exceeded."); return name; }
  }).parse(text);
  assertSbomStructure(xml);
  if (!xml.bom) throw new Error("Only CycloneDX XML is supported. Use JSON or SPDX text for other formats.");
  const bom = xml.bom;
  const components = [];
  const visit = (entries) => {
    for (const item of array(entries)) {
      components.push({ ...item, licenses: array(item.licenses?.license).map((license) => ({ license })), properties: array(item.properties?.property) });
      visit(item.components?.component);
    }
  };
  visit(bom.components?.component);
  return {
    bomFormat: "CycloneDX", specVersion: "XML", serialNumber: bom.serialNumber, metadata: bom.metadata,
    components,
    vulnerabilities: array(bom.vulnerabilities?.vulnerability).map((item) => ({
      ...item, ratings: array(item.ratings?.rating), affects: array(item.affects?.target),
      references: array(item.references?.reference), advisories: array(item.advisories?.advisory)
    }))
  };
}

function array(value) { return value === undefined ? [] : Array.isArray(value) ? value : [value]; }
