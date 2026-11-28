// Risk scores are computed once, server-side (backend/services/scoring.py), and the API
// returns risk_score / risk_band. This file only maps a score or band to its severity colour.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const SEVERITY_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

// Normalises the API's band or severity ("HIGH", "High", "critical") to a key above; unknown -> null
export const severityKey = (value) => {
  const key = String(value || '').toLowerCase();
  return SEVERITIES.includes(key) ? key : null;
};

// Colour bands for a score, the same thresholds scoring.py uses for risk_band
const scoreSeverity = (score) => {
  if (score >= 86) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 31) return 'medium';
  return 'low';
};

export const getRiskColor = (score) => `var(--sev-${scoreSeverity(score)})`;

// Same colours keyed by the band name the API returns; unknown or empty -> muted text
export const getBandColor = (band) => {
  const key = severityKey(band);
  return key ? `var(--sev-${key})` : 'var(--text-3)';
};
