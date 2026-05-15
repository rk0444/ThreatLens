export const getRiskScore = (cve) => {
  const cvssComponent     = ((cve.cvss_score || 0) / 10) * 100 * 0.25;
  const epssComponent     = (cve.epss_score || 0) * 100 * 0.20;
  const kevComponent      = cve.cisa_kev ? 100 * 0.15 : 0;
  const exploitComponent  = cve.actively_exploited ? 100 * 0.10 : 0;
  const assetComponent    = cve.asset_affected ? 100 * 0.10 : 0;

  const exposureComponent = (() => {
    const count = cve.affected_asset_count || 0;
    if (!cve.asset_affected) return 0;
    if (count >= 10) return 100 * 0.05;
    if (count >= 5)  return 75  * 0.05;
    if (count >= 2)  return 50  * 0.05;
    return            25  * 0.05;
  })();

  const threatComponent   = cve.ransomware_use ? 100 * 0.05 : 0;
  const patchComponent    = cve.patch_available === false ? 100 * 0.05 : 0;

  const temporalComponent = (() => {
    const days = (Date.now() - new Date(cve.published_date || 0).getTime())
                 / (1000 * 60 * 60 * 24);
    if (days <= 7)  return 100 * 0.05;
    if (days <= 30) return 60  * 0.05;
    if (days <= 90) return 30  * 0.05;
    return 0;
  })();

  return Math.min(100, Math.round(
    cvssComponent + epssComponent + kevComponent + exploitComponent +
    assetComponent + exposureComponent + threatComponent +
    patchComponent + temporalComponent
  ));
};

export const getRiskColor = (score) => {
  if (score >= 86) return 'var(--danger)';
  if (score >= 61) return 'var(--warning)';
  if (score >= 31) return 'var(--accent-gold)';
  return 'var(--success)';
};