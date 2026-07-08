import React, { useMemo, useState } from "react";

const SEVERITY_COLORS = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || "var(--text-dim)";
  return (
    <span
      className="sev-badge"
      style={{ color, background: `${color}22`, border: `1px solid ${color}55` }}
    >
      {severity}
    </span>
  );
}

export default function FindingsTable({ findings }) {
  const [activeSeverity, setActiveSeverity] = useState("ALL");

  const filtered = useMemo(() => {
    if (activeSeverity === "ALL") return findings;
    return findings.filter((f) => f.severity === activeSeverity);
  }, [findings, activeSeverity]);

  const severities = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div>
      <div className="filter-bar">
        {severities.map((sev) => (
          <button
            key={sev}
            className={`filter-btn ${activeSeverity === sev ? "active" : ""}`}
            onClick={() => setActiveSeverity(sev)}
          >
            {sev}
          </button>
        ))}
      </div>

      <table className="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Resource</th>
            <th>Finding</th>
            <th>Detected</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((f) => (
            <tr key={f.finding_id}>
              <td><SeverityBadge severity={f.severity} /></td>
              <td className="resource-id">{f.resource_id}</td>
              <td>{f.message}</td>
              <td style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                {new Date(f.detected_at).toLocaleString()}
              </td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={4} style={{ color: "var(--text-dim)", textAlign: "center", padding: "24px 0" }}>
                No findings for this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
