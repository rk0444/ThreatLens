// Risk scores are computed once, server-side (backend/services/scoring.py), and the API
// returns risk_score / risk_band. This file only maps a score to its band colour.
export const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return 'var(--warning)';
  if (score >= 31) return 'var(--accent-gold)';
  return 'var(--success)';
};
