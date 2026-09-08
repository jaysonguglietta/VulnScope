export function createSbomBudget({ maxRecords = 20000, maxBytes = 16 * 1024 * 1024, deadlineMs = 15000 } = {}) {
  let records = 0;
  const deadline = Date.now() + deadlineMs;
  return {
    spend(count = 1) {
      records += count;
      if (records > maxRecords || Date.now() > deadline) throw new Error("SBOM processing limit reached. Split the inventory into smaller files.");
    },
    check(value) {
      assertSbomStructure(value);
      if (new TextEncoder().encode(JSON.stringify(value)).byteLength > maxBytes) throw new Error("Normalized SBOM exceeds the output byte limit.");
      this.spend(0);
    }
  };
}

export function assertSbomStructure(value) {
  const pending = [[value, 0]];
  let nodes = 0;
  while (pending.length) {
    const [item, depth] = pending.pop();
    if (++nodes > 200000 || depth > 40) throw new Error("SBOM structure exceeds the node or depth limit.");
    if (typeof item === "string" && item.length > 8192) throw new Error("SBOM field exceeds 8,192 characters.");
    if (item && typeof item === "object") {
      const entries = Object.entries(item);
      if (entries.length > 20000) throw new Error("SBOM collection exceeds 20,000 entries.");
      for (const [key, child] of entries) {
        if (["__proto__", "constructor", "prototype"].includes(key)) throw new Error("Unsafe SBOM property name.");
        pending.push([child, depth + 1]);
      }
    }
  }
}
