import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { researchCve } from "./server.mjs";
import { createHash } from "node:crypto";

const dynamodb = new DynamoDBClient({});
const sns = new SNSClient({});

export const handler = createMonitorHandler();

export function createMonitorHandler({
  research = researchCve, load = loadMonitorState, save = saveMonitorState,
  publish = (message) => sns.send(new PublishCommand(message))
} = {}) {
  return async function runMonitor() {
    const cves = monitoredCves();
    const tableName = process.env.MONITOR_TABLE_NAME;
    const topicArn = process.env.MONITOR_TOPIC_ARN;
    if (!cves.length || !tableName || !topicArn) return { monitored: 0, changed: 0 };
    const notifications = [], failures = [];
    for (const cve of cves) {
      try {
        const state = await load(tableName, cve);
        // A pending change is replayed even if its source is unavailable today.
        if (state.pending) { notifications.push({ ...state.pending, revision: state.revision }); continue; }
        const result = await research(cve);
        if (!hasPrimaryCveRecord(result) || !["kev", "epss"].every((id) => result.sourceResults?.some((source) => source.id === id && source.status === "ok"))) {
          throw new Error("Required CVE, KEV or EPSS source unavailable; baseline preserved.");
        }
        const snapshot = makeSnapshot(result);
        const changes = state.snapshot ? materialChanges(state.snapshot, snapshot) : [];
        if (!changes.length) {
          await save(tableName, cve, { snapshot, pending: null }, state.revision);
          continue;
        }
        const eventId = createHash("sha256").update(JSON.stringify([cve, state.snapshot, snapshot])).digest("hex");
        const pending = { eventId, cve, title: result.title, snapshot, changes };
        await save(tableName, cve, { snapshot: state.snapshot, pending }, state.revision);
        notifications.push({ ...pending, revision: state.revision + 1 });
      } catch (error) { failures.push({ cve, message: safeMessage(error) }); }
    }
    if (notifications.length) {
      await publish({
        TopicArn: topicArn,
        Subject: "VulnScope: " + notifications.length + " monitored CVE changes",
        Message: makeNotification(notifications, failures)
      });
      for (const item of notifications) {
        try { await save(tableName, item.cve, { snapshot: item.snapshot, pending: null }, item.revision); }
        catch (error) { failures.push({ cve: item.cve, message: safeMessage(error) }); }
      }
    }
    // Fail the invocation for retry/health metrics; do not silently report success.
    if (failures.length) throw new Error("Monitor incomplete for " + failures.map((item) => item.cve).join(", ") + ". Pending changes and previous baselines were preserved.");
    return { monitored: cves.length, changed: notifications.length };
  };
}

function monitoredCves() {
  const values = [...new Set(String(process.env.MONITORED_CVES || "").toUpperCase().split(/[\s,]+/).filter(Boolean))];
  if (values.length > 25 || values.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw new Error("MONITORED_CVES must contain at most 25 valid CVE identifiers; no entries are omitted.");
  return values;
}

function makeSnapshot(research) {
  return {
    checkedAt: new Date().toISOString(),
    title: research.title || research.id,
    riskLevel: research.risk?.level || "Unknown",
    riskScore: research.risk?.score ?? null,
    verdict: research.realWorld?.verdict || "Unknown",
    exploited: research.realWorld?.exploitedStatus || "Unknown",
    maturity: research.exploitMaturity?.stage || "Unknown",
    kev: Boolean(research.metrics?.kev?.listed),
    epss: research.metrics?.epss?.epss ?? null,
    patchStatus: research.vendorPatch?.status || "Unknown",
    evidence: research.evidence?.length || 0,
    publicCode: research.realWorld?.counts?.publicCode || 0,
    references: research.references?.length || 0
  };
}

function materialChanges(before, after) {
  const changes = [];
  compare(changes, "Risk level", before.riskLevel, after.riskLevel);
  compare(changes, "Real-world verdict", before.verdict, after.verdict);
  compare(changes, "Exploitation status", before.exploited, after.exploited);
  compare(changes, "Exploit maturity", before.maturity, after.maturity);
  compare(changes, "Patch status", before.patchStatus, after.patchStatus);
  if (!before.kev && after.kev) changes.push({ label: "CISA KEV", before: "Not listed", after: "Listed" });
  if (numericIncrease(before.epss, after.epss) >= 0.1) changes.push({ label: "EPSS", before: percent(before.epss), after: percent(after.epss) });
  if ((after.publicCode || 0) > (before.publicCode || 0)) changes.push({ label: "Public code leads", before: before.publicCode || 0, after: after.publicCode || 0 });
  if ((after.evidence || 0) >= (before.evidence || 0) + 3) changes.push({ label: "Evidence count", before: before.evidence || 0, after: after.evidence || 0 });
  return changes;
}

function compare(changes, label, before, after) {
  if (before !== after) changes.push({ label, before: before ?? "n/a", after: after ?? "n/a" });
}

function numericIncrease(before, after) {
  const left = Number(before);
  const right = Number(after);
  return Number.isFinite(left) && Number.isFinite(right) ? right - left : 0;
}

function hasPrimaryCveRecord(research) {
  return (research?.sourceResults || []).some((source) => ["nvd", "cve"].includes(source.id) && source.status === "ok");
}

async function loadMonitorState(tableName, cve) {
  const response = await dynamodb.send(new GetItemCommand({ TableName: tableName, Key: { cve: { S: cve } }, ConsistentRead: true }));
  const item = response.Item;
  return {
    snapshot: item?.snapshot?.S ? JSON.parse(item.snapshot.S) : null,
    pending: item?.pending?.S ? JSON.parse(item.pending.S) : null,
    revision: Number(item?.revision?.N || 0)
  };
}

async function saveMonitorState(tableName, cve, state, revision) {
  const item = {
    cve: { S: cve }, snapshot: { S: JSON.stringify(state.snapshot) },
    revision: { N: String(revision + 1) }, updatedAt: { S: new Date().toISOString() }
  };
  if (state.pending) item.pending = { S: JSON.stringify(state.pending) };
  // Pending notifications must not expire before delivery is accepted.
  else item.expiresAt = { N: String(Math.floor(Date.now() / 1000) + 180 * 24 * 60 * 60) };
  await dynamodb.send(new PutItemCommand({
    TableName: tableName, Item: item,
    ConditionExpression: revision ? "#revision = :revision" : "attribute_not_exists(#revision)",
    ExpressionAttributeNames: { "#revision": "revision" },
    ...(revision ? { ExpressionAttributeValues: { ":revision": { N: String(revision) } } } : {})
  }));
}

function makeNotification(notifications, failures) {
  const lines = [
    "VulnScope detected material changes in the scheduled CVE watchlist.",
    ""
  ];
  for (const item of notifications) {
    lines.push(`${item.cve}: ${item.title}`);
    lines.push(`Notification ID: ${item.eventId}`);
    for (const change of item.changes) lines.push(`- ${change.label}: ${change.before} -> ${change.after}`);
    lines.push(`- Current risk: ${item.snapshot.riskLevel} ${item.snapshot.riskScore ?? ""}`.trim());
    lines.push(`- Review: https://vulnscope.jsontechnology.com/?cve=${encodeURIComponent(item.cve)}`);
    lines.push("");
  }
  if (failures.length) {
    lines.push("Sources that could not be refreshed:");
    for (const failure of failures) lines.push(`- ${failure.cve}: ${failure.message}`);
  }
  lines.push("This notification reports intelligence changes, not confirmed exposure in your environment.");
  return lines.join("\n");
}

function percent(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${(number * 100).toFixed(1)}%` : "n/a";
}

function safeMessage(error) {
  return String(error?.message || "monitor failed").slice(0, 240);
}
