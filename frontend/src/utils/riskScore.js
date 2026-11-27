// Risk scores are computed once, server-side (backend/services/scoring.py), and the API
// returns risk_score / risk_band. This file only maps a score to its band colour.
export const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return 'var(--warning)';
  if (score >= 31) return 'var(--accent-gold)';
  return 'var(--success)';
};

// Same colours keyed by the band name the API returns ("HIGH", "High"); unknown or empty -> muted
const BAND_COLORS = { CRITICAL: 'var(--danger)', HIGH: 'var(--warning)', MEDIUM: 'var(--accent-gold)', LOW: 'var(--success)' };
export const getBandColor = (band) => BAND_COLORS[String(band || '').toUpperCase()] || 'var(--text-muted)';
