import { execFileSync } from "node:child_process";

// Explicit operator invocation only. No resource mutations or email sends.
const region = process.env.AWS_REGION || "us-east-1";
const stack = process.env.STACK_NAME || "vulnscope-prod";
const profile = process.env.AWS_PROFILE || "json";
function aws(service, operation, args = [], query) {
  const stdout = execFileSync("aws", [service, operation, ...args, "--region", region, "--profile", profile, "--output", "json", ...(query ? ["--query", query] : [])], { encoding: "utf8", timeout: 20000, maxBuffer: 2 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, AWS_PAGER: "" } });
  return JSON.parse(stdout);
}
try {
  const identity = aws("sts", "get-caller-identity", [], "{Account:Account}");
  if (identity.Account !== (process.env.EXPECTED_AWS_ACCOUNT_ID || "171058045575")) throw new Error("Account does not match EXPECTED_AWS_ACCOUNT_ID.");
  const info = aws("cloudformation", "describe-stacks", ["--stack-name", stack], "Stacks[0].{Status:StackStatus,Outputs:Outputs}");
  const topic = info.Outputs?.find((o) => o.OutputKey === "MonitorTopicArn")?.OutputValue;
  const report = { checkedAt: new Date().toISOString(), account: identity.Account, region, stack, stackStatus: info.Status, monitor: topic ? "configured" : "disabled", delivery: "not verified; API acceptance does not prove inbox receipt" };
  if (topic) {
    const resources = aws("cloudformation", "describe-stack-resources", ["--stack-name", stack], "StackResources[].{logical:LogicalResourceId,physical:PhysicalResourceId}");
    const functionName = resources.find((r) => r.logical === "MonitorFunction")?.physical;
    const rule = resources.find((r) => r.logical === "MonitorSchedule")?.physical;
    const subscriptions = aws("sns", "list-subscriptions-by-topic", ["--topic-arn", topic], "Subscriptions[].{Protocol:Protocol,Arn:SubscriptionArn}");
    report.subscriptions = { confirmed: subscriptions.filter((s) => s.Protocol === "email" && String(s.Arn).startsWith("arn:")).length, pending: subscriptions.filter((s) => s.Arn === "PendingConfirmation").length };
    if (functionName) report.function = aws("lambda", "get-function-configuration", ["--function-name", functionName], "{State:State,LastUpdateStatus:LastUpdateStatus,Runtime:Runtime,Timeout:Timeout,MonitoredCves:Environment.Variables.MONITORED_CVES}");
    if (rule) report.schedule = aws("events", "describe-rule", ["--name", rule], "{State:State,ScheduleExpression:ScheduleExpression}");
    report.nextChecks = ["Inspect Lambda Errors and Invocations metrics for this function.", "Read only the intended CVE keys in the monitor DynamoDB table: pending.eventId is unresolved delivery; snapshot.checkedAt is the last accepted baseline.", "Verify one authorized notification in the recipient inbox. This script does not invoke the monitor or send email."];
  }
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  console.error(error.message?.startsWith("Account does") ? error.message : "Monitor status unverified: AWS credentials, permissions, account or stack unavailable. No resources changed. Run individual read-only checks from docs/deployment.md for diagnosis.");
  process.exitCode = 1;
}
