import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { researchCve } from "./server.mjs";

const dynamodb = new DynamoDBClient({});
const sns = new SNSClient({});

export async function handler() {
  const cves = monitoredCves();
  const tableName = process.env.MONITOR_TABLE_NAME;
  const topicArn = process.env.MONITOR_TOPIC_ARN;
  if (!cves.length || !tableName || !topicArn) {
    return { monitored: 0, changed: 0, message: "Scheduled monitoring is not configured." };
  }

  const notifications = [];
  const failures = [];
  for (const cve of cves) {
    try {
      const research = await researchCve(cve);
      if (!hasPrimaryCveRecord(research)) {
        throw new Error("No primary CVE record source succeeded; the previous baseline was preserved.");
      }
      const snapshot = makeSnapshot(research);
      const previous = await loadSnapshot(tableName, cve);
      const changes = previous ? materialChanges(previous, snapshot) : [];
      await saveSnapshot(tableName, cve, snapshot);
      if (changes.length) notifications.push({ cve, title: research.title, changes, snapshot });
    } catch (error) {
      failures.push({ cve, message: safeMessage(error) });
    }
  }

  if (notifications.length) {
    await sns.send(new PublishCommand({
      TopicArn: topicArn,
      Subject: `VulnScope: ${notifications.length} monitored CVE change${notifications.length === 1 ? "" : "s"}`.slice(0, 100),
      Message: makeNotification(notifications, failures)
    }));
  }
  return { monitored: cves.length, changed: notifications.length, failures };
}

function monitoredCves() {
  return [...new Set(String(process.env.MONITORED_CVES || "")
    .toUpperCase()
    .match(/CVE-\d{4}-\d{4,}/g) || [])].slice(0, 25);
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

async function loadSnapshot(tableName, cve) {
  const response = await dynamodb.send(new GetItemCommand({
    TableName: tableName,
    Key: { cve: { S: cve } },
    ConsistentRead: true
  }));
  const value = response.Item?.snapshot?.S;
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

async function saveSnapshot(tableName, cve, snapshot) {
  const expiresAt = Math.floor(Date.now() / 1000) + 180 * 24 * 60 * 60;
  await dynamodb.send(new PutItemCommand({
    TableName: tableName,
    Item: {
      cve: { S: cve },
      snapshot: { S: JSON.stringify(snapshot) },
      updatedAt: { S: snapshot.checkedAt },
      expiresAt: { N: String(expiresAt) }
    }
  }));
}

function makeNotification(notifications, failures) {
  const lines = [
    "VulnScope detected material changes in the scheduled CVE watchlist.",
    ""
  ];
  for (const item of notifications) {
    lines.push(`${item.cve}: ${item.title}`);
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
