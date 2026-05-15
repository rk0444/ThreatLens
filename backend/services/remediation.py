import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
import json

from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage

from ..database import models
from ..database.threat_schema import RemediationPlaybook, RemediationStep

logger = logging.getLogger(__name__)

class RemediationService:
    """AI-powered incident remediation playbook generation service"""
    
    def __init__(self):
        # Initialize OpenAI for high-quality playbook generation
        self.openai_llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.2
        )
        
        logger.info("Remediation service initialized")
    
    async def generate_playbook(self, db_session: Session, incident_id: int) -> Optional[RemediationPlaybook]:
        """Generate remediation playbook for a specific incident"""
        try:
            logger.info(f"Generating remediation playbook for incident {incident_id}")
            
            # Get incident details
            incident = db_session.query(models.Incident).filter(
                models.Incident.id == incident_id
            ).first()
            
            if not incident:
                logger.error(f"Incident {incident_id} not found")
                return None
            
            # Get related asset information
            asset = None
            if incident.machine_id:
                asset = db_session.query(models.Asset).filter(
                    models.Asset.id == incident.machine_id
                ).first()
            
            # Get related CVEs if any
            related_cves = []
            if incident.mitre_tags:
                # Look for CVEs that might be related to this incident
                related_cves = db_session.query(models.CVE).filter(
                    models.CVE.actively_exploited == True
                ).limit(5).all()
            
            # Build the AI prompt
            prompt = self._build_playbook_prompt(incident, asset, related_cves)
            
            # Generate playbook using GPT-4o
            response = await self.openai_llm.ainvoke([HumanMessage(content=prompt)])
            
            # Parse the response
            playbook_data = self._parse_playbook_response(response.content)
            
            # Create remediation playbook
            playbook = RemediationPlaybook(
                incident_id=incident_id,
                threat_id=f"incident-{incident_id}",
                total_steps=len(playbook_data["steps"]),
                steps=playbook_data["steps"],
                confidence_score=playbook_data.get("confidence", 0.8)
            )
            
            logger.info(f"Remediation playbook generated for incident {incident_id} with {len(playbook.steps)} steps")
            
            return playbook
            
        except Exception as e:
            logger.error(f"Failed to generate remediation playbook for incident {incident_id}: {str(e)}")
            return self._create_fallback_playbook(incident_id)
    
    def _build_playbook_prompt(self, incident: models.Incident, 
                              asset: Optional[models.Asset], 
                              related_cves: List[models.CVE]) -> str:
        """Build AI prompt for remediation playbook generation"""
        
        prompt = f"""
You are a senior cybersecurity incident response specialist. Generate a detailed remediation playbook for this security incident.

INCIDENT DETAILS:
- Incident ID: {incident.id}
- Type: {incident.type}
- Severity: {incident.severity}
- Status: {incident.status}
- Description: {incident.details or 'No description available'}
- Process Name: {incident.process_name or 'Unknown'}
- File Path: {incident.file_path or 'Unknown'}
- Network Connection: {incident.network_connection or 'Unknown'}
- Sandbox Verdict: {incident.sandbox_verdict or 'Not available'}
- MITRE Tags: {', '.join(incident.mitre_tags) if incident.mitre_tags else 'None'}
- Timeline: {json.dumps(incident.timeline) if incident.timeline else 'No timeline available'}
"""
        
        if asset:
            prompt += f"""
AFFECTED ASSET:
- Asset Name: {asset.name}
- IP Address: {asset.ip_address}
- Operating System: {asset.os}
- Software List: {', '.join(asset.software_list) if asset.software_list else 'Unknown'}
- Status: {asset.status}
"""
        
        if related_cves:
            prompt += f"""
RELATED VULNERABILITIES:
"""
            for cve in related_cves[:3]:
                prompt += f"""
- {cve.cve_id}: {cve.description[:100]}{'...' if len(cve.description) > 100 else ''}
  CVSS Score: {cve.cvss_score or 'N/A'}
  Actively Exploited: {cve.actively_exploited or 'No'}
"""
        
        prompt += """

TASK: Generate a step-by-step remediation playbook following this JSON structure:

{
    "steps": [
        {
            "step": 1,
            "action": "Specific action to take",
            "command": "Exact command to run (if applicable)",
            "priority": "immediate|high|medium|low",
            "estimated_time": "Time estimate (e.g., '5 minutes', '1 hour')",
            "risk_level": "low|medium|high|critical"
        }
    ],
    "confidence": 0.9,
    "total_estimated_time": "Overall time estimate"
}

GUIDELINES:
1. Start with immediate containment actions
2. Include investigation and analysis steps
3. Provide eradication and recovery procedures
4. Add post-incident follow-up tasks
5. Include specific commands when applicable
6. Prioritize actions based on incident severity
7. Consider the MITRE ATT&CK stage when determining response
8. Include safety warnings for high-risk commands
9. Provide realistic time estimates
10. Focus on practical, actionable steps

Return only valid JSON that can be parsed.
"""
        
        return prompt
    
    def _parse_playbook_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured playbook data"""
        try:
            # Try to extract JSON from the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                data = json.loads(json_str)
                
                # Validate and format steps
                steps = []
                for i, step_data in enumerate(data.get("steps", []), 1):
                    step = RemediationStep(
                        step=step_data.get("step", i),
                        action=step_data.get("action", "Unknown action"),
                        command=step_data.get("command"),
                        priority=step_data.get("priority", "medium"),
                        estimated_time=step_data.get("estimated_time"),
                        risk_level=step_data.get("risk_level", "medium")
                    )
                    steps.append(step)
                
                return {
                    "steps": steps,
                    "confidence": data.get("confidence", 0.8),
                    "total_estimated_time": data.get("total_estimated_time")
                }
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse playbook JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error parsing playbook response: {str(e)}")
        
        # Fallback to manual parsing
        return self._create_fallback_steps()
    
    def _create_fallback_steps(self) -> Dict[str, Any]:
        """Create fallback remediation steps"""
        steps = [
            RemediationStep(
                step=1,
                action="Isolate affected system from network",
                command="netsh interface set interface \"Ethernet\" disable",
                priority="immediate",
                estimated_time="2 minutes",
                risk_level="low"
            ),
            RemediationStep(
                step=2,
                action="Terminate suspicious processes",
                command="tasklist /fi \"imagename eq {process_name}\"",
                priority="immediate",
                estimated_time="5 minutes",
                risk_level="medium"
            ),
            RemediationStep(
                step=3,
                action="Collect forensic evidence",
                command="mkdir C:\\forensics && copy {file_path} C:\\forensics\\",
                priority="high",
                estimated_time="15 minutes",
                risk_level="low"
            ),
            RemediationStep(
                step=4,
                action="Scan for additional malware",
                command="powershell -Command \"Start-MpScan -ScanType CustomScan -ScanPath C:\\\"",
                priority="high",
                estimated_time="30 minutes",
                risk_level="low"
            ),
            RemediationStep(
                step=5,
                action="Review and update security controls",
                command=None,
                priority="medium",
                estimated_time="1 hour",
                risk_level="low"
            )
        ]
        
        return {
            "steps": steps,
            "confidence": 0.6,
            "total_estimated_time": "Approximately 2 hours"
        }
    
    def _create_fallback_playbook(self, incident_id: int) -> RemediationPlaybook:
        """Create a fallback playbook if AI generation fails"""
        fallback_steps = self._create_fallback_steps()
        
        return RemediationPlaybook(
            incident_id=incident_id,
            threat_id=f"incident-{incident_id}",
            total_steps=len(fallback_steps["steps"]),
            steps=fallback_steps["steps"],
            confidence_score=0.5
        )
    
    def get_playbook_template(self, incident_type: str, severity: str) -> Dict[str, Any]:
        """Get template-based playbook for common incident types"""
        templates = {
            "malware": {
                "critical": {
                    "steps": [
                        {"step": 1, "action": "Immediate network isolation", "command": "netsh interface set interface \"Ethernet\" disable", "priority": "immediate", "estimated_time": "2 minutes", "risk_level": "low"},
                        {"step": 2, "action": "Terminate malicious processes", "command": "taskkill /f /im {process_name}", "priority": "immediate", "estimated_time": "5 minutes", "risk_level": "medium"},
                        {"step": 3, "action": "Disable compromised accounts", "command": "net user {username} /active:no", "priority": "immediate", "estimated_time": "3 minutes", "risk_level": "low"},
                        {"step": 4, "action": "Run full system scan", "command": "powershell -Command \"Start-MpScan -ScanType FullScan\"", "priority": "high", "estimated_time": "1 hour", "risk_level": "low"},
                        {"step": 5, "action": "Collect memory dump for analysis", "command": "procdump -ma {pid} C:\\forensics\\memory.dmp", "priority": "medium", "estimated_time": "15 minutes", "risk_level": "low"}
                    ]
                }
            },
            "unauthorized_access": {
                "high": {
                    "steps": [
                        {"step": 1, "action": "Force password reset for compromised accounts", "command": "net user {username} *", "priority": "immediate", "estimated_time": "5 minutes", "risk_level": "low"},
                        {"step": 2, "action": "Review recent login attempts", "command": "wevtutil qe Security /c:100 /rd:true /f:text", "priority": "immediate", "estimated_time": "10 minutes", "risk_level": "low"},
                        {"step": 3, "action": "Check for privilege escalation", "command": "whoami /priv", "priority": "high", "estimated_time": "5 minutes", "risk_level": "low"},
                        {"step": 4, "action": "Audit running services", "command": "sc query type= service state= running", "priority": "medium", "estimated_time": "15 minutes", "risk_level": "low"},
                        {"step": 5, "action": "Enable additional logging", "command": "auditpol /set /category:\"Logon/Logoff\" /success:enable /failure:enable", "priority": "medium", "estimated_time": "10 minutes", "risk_level": "low"}
                    ]
                }
            },
            "data_exfiltration": {
                "critical": {
                    "steps": [
                        {"step": 1, "action": "Block outbound network connections", "command": "netsh advfirewall firewall add rule name=\"Block Outbound\" dir=out action=block", "priority": "immediate", "estimated_time": "2 minutes", "risk_level": "medium"},
                        {"step": 2, "action": "Identify data transfer processes", "command": "netstat -ano | findstr ESTABLISHED", "priority": "immediate", "estimated_time": "5 minutes", "risk_level": "low"},
                        {"step": 3, "action": "Secure sensitive data repositories", "command": "icacls \"C:\\Sensitive Data\" /deny Everyone:(F)", "priority": "immediate", "estimated_time": "3 minutes", "risk_level": "low"},
                        {"step": 4, "action": "Analyze network traffic logs", "command": "Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {$_.Id -eq 5156}", "priority": "high", "estimated_time": "30 minutes", "risk_level": "low"},
                        {"step": 5, "action": "Implement data loss prevention controls", "command": None, "priority": "medium", "estimated_time": "2 hours", "risk_level": "low"}
                    ]
                }
            }
        }
        
        return templates.get(incident_type, {}).get(severity, {})
    
    def validate_playbook_step(self, step: RemediationStep) -> List[str]:
        """Validate a remediation step and return warnings"""
        warnings = []
        
        # Check for dangerous commands
        if step.command:
            dangerous_commands = [
                "format", "del ", "rmdir", "shutdown", "reboot",
                "reg delete", "bcdedit", "diskpart"
            ]
            
            for dangerous in dangerous_commands:
                if dangerous in step.command.lower():
                    warnings.append(f"⚠️ Potentially dangerous command detected: {dangerous}")
        
        # Check priority vs risk level consistency
        if step.priority == "immediate" and step.risk_level == "critical":
            warnings.append("⚠️ Immediate priority with critical risk - ensure proper authorization")
        
        # Check for missing command in high-priority steps
        if step.priority in ["immediate", "high"] and not step.command:
            warnings.append("⚠️ High-priority step missing specific command")
        
        return warnings

# Global service instance
_remediation_service = None

def get_remediation_service() -> RemediationService:
    """Get the global remediation service instance"""
    global _remediation_service
    if _remediation_service is None:
        _remediation_service = RemediationService()
    return _remediation_service
