/**
 * SENTINEL-X — Frontend API Client
 * Centralised fetch wrapper for all backend endpoints.
 * Backend base URL can be overridden via VITE_API_BASE env var.
 */

const BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Health ─────────────────────────────────────────────────────────────────
export const getHealth = () => request("/health");

// ── Analyze Input (no LLM call) ────────────────────────────────────────────
export const analyzeInput = (text, sessionId, source = "USER_INPUT") =>
  request("/api/v1/analyze/input", {
    method: "POST",
    body: JSON.stringify({ text, session_id: sessionId, source }),
  });

// ── Chat (full pipeline) ───────────────────────────────────────────────────
export const sendChat = (text, sessionId, systemPrompt = null) =>
  request("/api/v1/chat", {
    method: "POST",
    body: JSON.stringify({
      text,
      session_id: sessionId,
      system_prompt: systemPrompt || undefined,
    }),
  });

// ── Audit Logs ─────────────────────────────────────────────────────────────
export const getAuditLogs = ({ limit = 50, offset = 0, decision, session_id } = {}) => {
  const params = new URLSearchParams({ limit, offset });
  if (decision) params.set("decision", decision);
  if (session_id) params.set("session_id", session_id);
  return request(`/api/v1/audit/logs?${params}`);
};

// ── Audit Stats ────────────────────────────────────────────────────────────
export const getAuditStats = () => request("/api/v1/audit/stats");

// ── Session History ────────────────────────────────────────────────────────
export const getSessionHistory = (sessionId) =>
  request(`/api/v1/audit/session/${sessionId}`);
