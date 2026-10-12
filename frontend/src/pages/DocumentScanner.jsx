
import React, { useRef, useState } from "react";
import { analyzeDocument } from "../api/sentinel";

export default function DocumentScanner() {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function chooseFile(event) {
    const selected = event.target.files?.[0] ?? null;
    setError("");
    setReport(null);

    if (!selected) {
      setFile(null);
      return;
    }

    if (!/\.(pdf|docx|txt)$/i.test(selected.name)) {
      setFile(null);
      setError("Choose a PDF, DOCX, or TXT file.");
      event.target.value = "";
      return;
    }

    if (selected.size > 10 * 1024 * 1024) {
      setFile(null);
      setError("Maximum file size is 10 MB.");
      event.target.value = "";
      return;
    }

    setFile(selected);
  }

  async function scanDocument() {
    if (!file || loading) {
      setError("Please attach a document before scanning.");
      return;
    }

    setLoading(true);
    setError("");
    setReport(null);

    try {
      setReport(await analyzeDocument(file));
    } catch (err) {
      setError(err.message || "Document scan failed.");
    } finally {
      setLoading(false);
    }
  }

  const analysis = report?.report;

  const buttonStyle = {
    display: "inline-block",
    padding: "12px 24px",
    background: !file || loading ? "#64748b" : "#2563eb",
    color: "#ffffff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 600,
    cursor: loading ? "wait" : "pointer",
    opacity: loading ? 0.8 : 1,
  };

  return (
    <main
      style={{
        padding: 24,
        maxWidth: 1000,
        margin: "0 auto",
        color: "var(--text-color, inherit)",
        overflowY: "auto",
      }}
    >
      <h2>Document Scanner</h2>
      <p>
        Attach a document and scan it for prompt injection, sensitive
        information, exposed secrets, and security risks.
      </p>

      <section
        style={{
          marginTop: 24,
          padding: 24,
          border: "1px solid var(--border, #777)",
          borderRadius: 12,
        }}
      >
        <h3>Attach Document</h3>
        <p>Supported formats: PDF, DOCX, TXT. Maximum size: 10 MB.</p>

        <input
          ref={inputRef}
          type="file"
          accept=".pdf,.docx,.txt"
          onChange={chooseFile}
          disabled={loading}
          aria-label="Choose a document"
        />

        {file && (
          <p style={{ marginTop: 12, overflowWrap: "anywhere" }}>
            Selected file: <strong>{file.name}</strong>
          </p>
        )}

        <div style={{ marginTop: 20 }}>
          <button
            type="button"
            onClick={scanDocument}
            disabled={!file || loading}
            style={buttonStyle}
          >
            {loading ? "Scanning document..." : "Scan Document"}
          </button>
        </div>

        {error && (
          <p role="alert" style={{ color: "#ff6b6b", marginTop: 16 }}>
            {error}
          </p>
        )}

        {loading && (
          <p role="status">Uploading and analyzing your document…</p>
        )}
      </section>

      {report && (
        <section style={{ marginTop: 24 }}>
          <h3>Security Report</h3>
          <p><strong>File:</strong> {report.filename}</p>
          <p>
            <strong>Extracted characters:</strong>{" "}
            {report.extracted_characters}
          </p>
          <p>
            <strong>Decision:</strong>{" "}
            {analysis?.decision ?? "See full report"}
          </p>
          <p>
            <strong>Risk score:</strong>{" "}
            {analysis?.risk?.score ?? "See full report"}
          </p>
          <p>
            <strong>Risk level:</strong>{" "}
            {analysis?.risk?.level ?? "See full report"}
          </p>

          <details>
            <summary>View full security report</summary>
            <pre
              style={{
                whiteSpace: "pre-wrap",
                overflowWrap: "anywhere",
                padding: 16,
                maxHeight: 600,
                overflow: "auto",
              }}
            >
              {JSON.stringify(analysis, null, 2)}
            </pre>
          </details>
        </section>
      )}
    </main>
  );
}
