// The API keys the backend reads (backend/services/*, backend/main.py), shared by Settings and Onboarding
export const KEY_FIELDS = [
  { name: 'NVD_API_KEY', label: 'NVD', hint: 'Faster CVE sync from the National Vulnerability Database.' },
  { name: 'OTX_API_KEY', label: 'AlienVault OTX', hint: 'OSINT pulses on Global Threats.' },
  { name: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB', hint: 'IP reputation for the network monitor and IOC Hunter.' },
  { name: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal', hint: 'File hash, URL and domain lookups in IOC Hunter.' },
  { name: 'GPT4O_API_KEY', label: 'GPT-4o', hint: 'AI Copilot, CVE summaries and the morning brief.' },
];
