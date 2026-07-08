/**
 * Thin client for the CloudSentinel API Gateway endpoints backed by
 * a small Lambda that reads from the findings / compliance-history
 * DynamoDB tables. Swap API_BASE_URL for your deployed API Gateway URL.
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://api.cloudsentinel.example.com";

async function request(path) {
  const res = await fetch(`${API_BASE_URL}${path}`);
  if (!res.ok) {
    throw new Error(`CloudSentinel API error ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

export const api = {
  getLatestScore: () => request("/compliance/latest"),
  getComplianceHistory: (days = 30) => request(`/compliance/history?days=${days}`),
  getFindings: ({ severity, resourceType } = {}) => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (resourceType) params.set("resource_type", resourceType);
    const qs = params.toString();
    return request(`/findings${qs ? `?${qs}` : ""}`);
  },
  getTopRisks: (limit = 5) => request(`/findings/top?limit=${limit}`),
};

/**
 * Demo/mock data so the dashboard renders something meaningful
 * even before the API is wired up — useful in interviews.
 */
export const mockLatestScore = {
  overall_score: 91,
  categories: { IAM: 96, S3: 88, Networking: 90, Encryption: 100, Monitoring: 85 },
  severity_counts: { CRITICAL: 1, HIGH: 3, MEDIUM: 8, LOW: 21 },
  total_findings: 33,
  scan_timestamp: new Date().toISOString(),
};

export const mockHistory = Array.from({ length: 14 }).map((_, i) => ({
  scan_date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(0, 10),
  overall_score: 78 + Math.round(Math.random() * 15),
}));

export const mockFindings = [
  { finding_id: "1", severity: "CRITICAL", resource_type: "S3_BUCKET", resource_id: "company-backup", message: "Bucket 'company-backup' may be publicly accessible.", detected_at: new Date().toISOString() },
  { finding_id: "2", severity: "HIGH", resource_type: "SECURITY_GROUP", resource_id: "sg-0a1b2c3d", message: "Security group exposes SSH (port 22) to the world.", detected_at: new Date().toISOString() },
  { finding_id: "3", severity: "HIGH", resource_type: "IAM_USER", resource_id: "svc-deploy", message: "User 'svc-deploy' has console access but no MFA device enabled.", detected_at: new Date().toISOString() },
  { finding_id: "4", severity: "MEDIUM", resource_type: "EBS_VOLUME", resource_id: "vol-0abc123", message: "Volume vol-0abc123 (100 GiB) is not encrypted.", detected_at: new Date().toISOString() },
];
