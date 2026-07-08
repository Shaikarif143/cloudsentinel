import React, { useEffect, useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import ScoreCard from "./components/ScoreCard.jsx";
import FindingsTable from "./components/FindingsTable.jsx";
import { api, mockLatestScore, mockHistory, mockFindings } from "./api.js";

const CATEGORY_ORDER = ["IAM", "S3", "Networking", "Encryption", "Monitoring"];

export default function App() {
  const [score, setScore] = useState(mockLatestScore);
  const [history, setHistory] = useState(mockHistory);
  const [findings, setFindings] = useState(mockFindings);
  const [usingLiveData, setUsingLiveData] = useState(false);

  useEffect(() => {
    // Try the real API; silently fall back to demo data if it isn't
    // deployed yet so the dashboard is always presentable.
    Promise.all([api.getLatestScore(), api.getComplianceHistory(14), api.getFindings()])
      .then(([latest, hist, findingsResp]) => {
        setScore(latest);
        setHistory(hist);
        setFindings(findingsResp);
        setUsingLiveData(true);
      })
      .catch(() => setUsingLiveData(false));
  }, []);

  return (
    <div className="sentinel-shell">
      <header className="sentinel-header">
        <div>
          <div className="sentinel-logo">// CloudSentinel</div>
          <h1 className="sentinel-title">AWS Cloud Security & Compliance</h1>
          <div className="sentinel-subtitle">
            {usingLiveData ? "live account data" : "demo data — connect API to go live"}
          </div>
        </div>
        <div className="sentinel-scan-meta">
          <div><span className="dot" />scanner active</div>
          <div>last scan: {new Date(score.scan_timestamp).toLocaleString()}</div>
        </div>
      </header>

      <section className="score-grid">
        <ScoreCard label="Overall Score" value={score.overall_score} overall />
        {CATEGORY_ORDER.map((cat) => (
          <ScoreCard key={cat} label={cat} value={score.categories[cat] ?? 0} />
        ))}
      </section>

      <section className="panels-row">
        <div className="panel">
          <h2>Compliance Score — Last 14 Days</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={history}>
              <CartesianGrid stroke="#232c3d" vertical={false} />
              <XAxis dataKey="scan_date" tick={{ fill: "#7c8aa3", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: "#7c8aa3", fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#161d2b", border: "1px solid #232c3d", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: "#7c8aa3" }}
              />
              <Line type="monotone" dataKey="overall_score" stroke="#4fd1c5" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <h2>Findings by Severity</h2>
          {Object.entries(score.severity_counts).map(([sev, count]) => (
            <div key={sev} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid var(--border-hair)" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-dim)" }}>{sev}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700 }}>{count}</span>
            </div>
          ))}
          <div className="severity-legend">
            <span className="severity-chip"><span className="swatch" style={{ background: "var(--sev-critical)" }} />Critical</span>
            <span className="severity-chip"><span className="swatch" style={{ background: "var(--sev-high)" }} />High</span>
            <span className="severity-chip"><span className="swatch" style={{ background: "var(--sev-medium)" }} />Medium</span>
            <span className="severity-chip"><span className="swatch" style={{ background: "var(--sev-low)" }} />Low</span>
          </div>
        </div>
      </section>

      <section className="panel">
        <h2>Findings ({findings.length})</h2>
        <FindingsTable findings={findings} />
      </section>
    </div>
  );
}
