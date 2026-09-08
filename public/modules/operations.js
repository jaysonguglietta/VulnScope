export class Operations {
  constructor() { this.active = new Map(); this.epoch = 0; }
  start(key) {
    this.cancel(key);
    const controller = new AbortController();
    const epoch = this.epoch;
    const operation = { signal: controller.signal, controller, current: () => !controller.signal.aborted && this.epoch === epoch && this.active.get(key) === operation };
    this.active.set(key, operation);
    return operation;
  }
  cancel(key) { this.active.get(key)?.controller.abort(); this.active.delete(key); }
  clear() { this.epoch++; for (const key of this.active.keys()) this.cancel(key); }
}

export function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const cancel = () => { clearTimeout(timer); reject(new DOMException("Operation cancelled", "AbortError")); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", cancel); resolve(); }, ms);
    signal?.addEventListener("abort", cancel, { once: true });
  });
}

export async function requestJson(url, options = {}) {
  const { signal, onWait = () => {}, timeout = 45000, retries = 2, ...init } = options;
  for (let attempt = 0; ; attempt++) {
    const timeoutSignal = AbortSignal.timeout(timeout);
    const response = await fetch(url, { ...init, signal: signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal });
    if (response.status === 429 && attempt < retries) {
      const header = response.headers.get("retry-after");
      const seconds = /^\d+$/.test(header || "") ? Number(header) : Math.ceil((Date.parse(header) - Date.now()) / 1000);
      const ms = Math.max(1000, Math.min(65000, (Number.isFinite(seconds) ? seconds : 60) * 1000));
      onWait(`Rate limited. Retrying in ${Math.ceil(ms / 1000)} seconds.`);
      await response.body?.cancel();
      await pause(ms, signal);
      continue;
    }
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.message || `Request failed (HTTP ${response.status}).`);
    return payload;
  }
}
