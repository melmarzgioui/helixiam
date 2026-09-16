/** A single platform component's health, as reported by `/admin/realms/{realm}/health`. */
export interface HealthComponent {
  name: string;
  status: string; // "up" | "down"
  detail: string;
}

export interface HealthSnapshot {
  overall: string; // "healthy" | "degraded"
  components: HealthComponent[];
  counts: Record<string, number>;
  checkedAt: string;
}

/**
 * Compact IAM metrics summary, as reported by `/admin/metrics/summary` (the raw Prometheus exposition
 * stays at `/actuator/prometheus` for scrapers). All counts are cumulative since process start.
 */
export interface MetricsSummary {
  realm: string | null;
  loginSuccess: number;
  loginFailure: number;
  loginTotal: number;
  loginSuccessRate: number | null; // 0..1 fraction, or null when there are no logins yet
  mfaSuccess: number;
  mfaFailure: number;
  tokensIssued: number;
  adminWrites: number;
  error?: string;
}

export interface HealthApi {
  get(realmId: string): Promise<HealthSnapshot>;
  /** Best-effort metrics summary; resolves null if the endpoint is unavailable (keeps the page additive). */
  metrics(realmId: string): Promise<MetricsSummary | null>;
}

/** HTTP-backed client for the realm health snapshot + metrics summary. */
export function createHealthHttpClient(baseUrl = ""): HealthApi {
  const base = baseUrl.replace(/\/$/, "");
  return {
    get: (realmId) =>
      fetch(`${base}/admin/realms/${encodeURIComponent(realmId)}/health`).then((res) => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res.json();
      }),
    metrics: (realmId) =>
      fetch(`${base}/admin/metrics/summary?realm=${encodeURIComponent(realmId)}`)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
  };
}
