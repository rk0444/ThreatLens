path = r'E:\Project\ThreatLens\backend\main.py'
content = open(path, encoding='utf-8').read()

old1 = "'severity': 'Critical' if cve.cvss_score >= 9.0 else 'High'"
new1 = "'severity': 'Critical' if (cve.cvss_score or 0) >= 9.0 else 'High'"

old2 = "'risk_score': threat.cvss_score * 10"
new2 = "'risk_score': (threat.cvss_score or 0) * 10"

content = content.replace(old1, new1)
content = content.replace(old2, new2)
open(path, 'w', encoding='utf-8').write(content)
print('Fixed')
