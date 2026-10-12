
/**
 * SENTINEL-X — Frontend API Client
 * Centralised fetch wrapper for all backend endpoints.
 * Backend base URL can be overridden via VITE_API_BASE env var.
 */

const BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

// ── Central request helper ─────────────────────────────────────────────────
async function request(path, options = {}) {
  const isFormData =
    typeof FormData !== "undefined" && options.body instanceof FormData;

  // Let the browser set multipart Content-Type and its boundary for uploads.
  // Keep JSON Content-Type for the existing JSON API requests.
  const headers = isFormData
    ? { ...options.headers }
    : { "Content-Type": "application/json", ...options.headers };

  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({
      detail: res.statusText || `HTTP ${res.status}`,
    }));

    const message =
      typeof err.detail === "string"
        ? err.detail
        : `HTTP ${res.status}`;

    throw new Error(message);
  }

  return res.json();
}

// ── Health ─────────────────────────────────────────────────────────────────
export const getHealth = () => request("/health");

// ── Analyze Input (no LLM call) ────────────────────────────────────────────
export const analyzeInput = (text, sessionId, source = "USER_INPUT") =>
  request("/api/v1/analyze/input", {
    method: "POST",
    body: JSON.stringify({
      text,
      session_id: sessionId,
      source,
    }),
  });

// ── Document Scanner ───────────────────────────────────────────────────────
// Upload a PDF, DOCX, or TXT file as multipart/form-data.
// Scanning starts when the user invokes this function.
export const analyzeDocument = (file) => {
  if (!file) {
    return Promise.reject(new Error("Please select a document first."));
  }

  const formData = new FormData();
  formData.append("file", file);

  return request("/api/v1/analyze/document", {
    method: "POST",
    body: formData,
  });
};

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
export const getAuditLogs = ({
  limit = 50,
  offset = 0,
  decision,
  session_id,
} = {}) => {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });

  if (decision) params.set("decision", decision);
  if (session_id) params.set("session_id", session_id);

  return request(`/api/v1/audit/logs?${params}`);
};

// ── Audit Stats ────────────────────────────────────────────────────────────
export const getAuditStats = () => request("/api/v1/audit/stats");

// ── Session History ────────────────────────────────────────────────────────
export const getSessionHistory = (sessionId) =>
  request(`/api/v1/audit/session/${encodeURIComponent(sessionId)}`);

// ── Quarantine ─────────────────────────────────────────────────────────────
export const getQuarantineLogs = () =>
  request("/api/v1/audit/quarantine");

export const actionQuarantine = (qId, action) =>
  request(
    `/api/v1/audit/quarantine/${encodeURIComponent(qId)}/action?action=${encodeURIComponent(action)}`,
    { method: "POST" }
  );
