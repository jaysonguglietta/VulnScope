const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function reportIdFromUrl(value, owner, name) {
  const url = new URL(value);
  const prefix = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/dependency-graph/sbom/fetch-report/`;
  if (url.origin !== "https://api.github.com" || url.username || url.password || url.search || url.hash || !url.pathname.startsWith(prefix)) throw new Error("GitHub returned an invalid report handle.");
  const id = url.pathname.slice(prefix.length);
  if (!UUID.test(id)) throw new Error("GitHub returned an invalid report ID.");
  return id;
}

export function allowedReportDownload(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && !u.port &&
      (u.hostname === "api.github.com" || u.hostname === "github.com" || u.hostname === "githubusercontent.com" || u.hostname.endsWith(".githubusercontent.com"));
  } catch { return false; }
}

export async function getAsyncSbom({ owner, name, jobId }, { json, read, fetch: fetcher = globalThis.fetch, signal }) {
  const prefix = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/dependency-graph/sbom`;
  const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2026-03-10", "user-agent": "VulnScope/0.4" };
  if (jobId && !UUID.test(jobId)) throw new Error("GitHub report ID is invalid.");
  if (!jobId) {
    const started = await json(prefix + "/generate-report", { headers });
    jobId = reportIdFromUrl(started?.sbom_url, owner, name);
  }
  let url = prefix + "/fetch-report/" + jobId;
  for (let redirects = 0; redirects <= 3; redirects++) {
    if (!allowedReportDownload(url)) throw new Error("GitHub report download host is not allowed; use lockfile inventory.");
    const response = await fetcher(url, { headers, redirect: "manual", signal });
    if (response.status === 202) { await response.body?.cancel(); return { pending: true, jobId }; }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location) throw new Error("GitHub report redirect has no destination.");
      url = new URL(location, url).href;
      continue;
    }
    if (!response.ok) { await response.body?.cancel(); throw new Error(`GitHub report returned ${response.status}.`); }
    const payload = JSON.parse(await read(response));
    return { payload: payload.sbom ? payload : { sbom: payload }, jobId };
  }
  throw new Error("GitHub report exceeded redirect limit.");
}
