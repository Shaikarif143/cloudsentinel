import React from "react";

/**
 * A single score tile. `overall` renders larger with the accent gradient
 * background; category tiles render smaller with a progress bar underneath.
 */
export default function ScoreCard({ label, value, overall = false }) {
  return (
    <div className={`score-card ${overall ? "overall" : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}%</div>
      {!overall && (
        <div className="bar-track">
          <div className="bar-fill" style={{ width: `${value}%` }} />
        </div>
      )}
    </div>
  );
}
