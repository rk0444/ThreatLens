import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
import json

from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage

from ..database import db, models
from .scoring import calculate_risk_score

logger = logging.getLogger(__name__)

class MorningBriefService:
    """AI-powered morning brief generation service"""
    
    def __init__(self):
        # Initialize OpenAI for high-quality brief generation
        self.openai_llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.4
        )
        
        logger.info("Morning Brief service initialized")
    
    async def generate_morning_brief(self, db_session: Session) -> models.MorningBrief:
        """Generate daily morning brief using AI"""
        try:
            logger.info("Starting morning brief generation")
            
            # Get data from the last 24 hours
            yesterday = datetime.utcnow() - timedelta(days=1)
            
            # Fetch top CVEs by risk score
            top_cves = self._get_top_cves(db_session, yesterday, limit=10)
            
            # Fetch active incidents from last 24 hours
            active_incidents = self._get_active_incidents(db_session, yesterday, limit=20)
            
            # Fetch OSINT alerts
            osint_alerts = self._get_osint_alerts(db_session, yesterday, limit=15)
            
            # Build the AI prompt
            prompt = self._build_morning_brief_prompt(top_cves, active_incidents, osint_alerts)
            
            # Generate brief using GPT-4o
            response = await self.openai_llm.ainvoke([HumanMessage(content=prompt)])
            
            # Parse the AI response
            brief_content = self._parse_morning_brief_response(response.content)
            
            # Extract structured data
            structured_data = self._extract_structured_data(response.content, top_cves, active_incidents)
            
            # Create and save morning brief
            morning_brief = models.MorningBrief(
                date=datetime.utcnow().date(),
                content=brief_content,
                top_threats=structured_data["top_threats"],
                active_incidents=structured_data["active_incidents"],
                patterns=structured_data["patterns"],
                actions=structured_data["actions"]
            )
            
            db_session.add(morning_brief)
            db_session.commit()
            
            logger.info(f"Morning brief generated successfully for {morning_brief.date}")
            
            return morning_brief
            
        except Exception as e:
            logger.error(f"Failed to generate morning brief: {str(e)}")
            # Create a fallback brief
            return self._create_fallback_brief(db_session)
    
    def _get_top_cves(self, db_session: Session, since_date: datetime, limit: int = 10) -> List[models.CVE]:
        """Get top CVEs by risk score from the last 24 hours"""
        try:
            cves = db_session.query(models.CVE).filter(
                models.CVE.published_date >= since_date
            ).all()
            
            # Calculate risk scores for each CVE
            cve_scores = []
            for cve in cves:
                risk_score = calculate_risk_score(
                    cvss_score=cve.cvss_score,
                    epss_score=cve.epss_score,
                    actively_exploited=cve.actively_exploited,
                    asset_affected=cve.asset_affected,
                    published_date=cve.published_date
                )
                
                cve_scores.append({
                    'cve': cve,
                    'risk_score': risk_score['score']
                })
            
            # Sort by risk score and return top N
            cve_scores.sort(key=lambda x: x['risk_score'], reverse=True)
            return [item['cve'] for item in cve_scores[:limit]]
            
        except Exception as e:
            logger.error(f"Failed to get top CVEs: {str(e)}")
            return []
    
    def _get_active_incidents(self, db_session: Session, since_date: datetime, limit: int = 20) -> List[models.Incident]:
        """Get active incidents from the last 24 hours"""
        try:
            return db_session.query(models.Incident).filter(
                models.Incident.created_at >= since_date
            ).order_by(desc(models.Incident.created_at)).limit(limit).all()
            
        except Exception as e:
            logger.error(f"Failed to get active incidents: {str(e)}")
            return []
    
    def _get_osint_alerts(self, db_session: Session, since_date: datetime, limit: int = 15) -> List[models.OSINTAlert]:
        """Get OSINT alerts from the last 24 hours"""
        try:
            return db_session.query(models.OSINTAlert).filter(
                models.OSINTAlert.created_at >= since_date
            ).order_by(desc(models.OSINTAlert.created_at)).limit(limit).all()
            
        except Exception as e:
            logger.error(f"Failed to get OSINT alerts: {str(e)}")
            return []
    
    def _build_morning_brief_prompt(self, top_cves: List[models.CVE], 
                                   active_incidents: List[models.Incident],
                                   osint_alerts: List[models.OSINTAlert]) -> str:
        """Build the AI prompt for morning brief generation"""
        
        prompt = f"""
You are a senior cybersecurity analyst generating a daily morning brief for the ThreatLens security team.

DATE: {datetime.utcnow().strftime('%Y-%m-%d')}

DATA SUMMARY:

TOP 10 CVEs BY RISK SCORE (Last 24 Hours):
"""
        
        for i, cve in enumerate(top_cves[:10], 1):
            risk_score = calculate_risk_score(
                cvss_score=cve.cvss_score,
                epss_score=cve.epss_score,
                actively_exploited=cve.actively_exploited,
                asset_affected=cve.asset_affected,
                published_date=cve.published_date
            )
            
            prompt += f"""
{i}. {cve.cve_id}
   Risk Score: {risk_score['score']:.1f} ({risk_score['band'].upper()})
   CVSS: {cve.cvss_score or 'N/A'}
   Actively Exploited: {cve.actively_exploited or 'No'}
   Description: {cve.description[:200]}{'...' if len(cve.description) > 200 else ''}
"""
        
        prompt += f"""

ACTIVE INCIDENTS (Last 24 Hours - Total: {len(active_incidents)}):
"""
        
        for i, incident in enumerate(active_incidents[:5], 1):
            prompt += f"""
{i}. {incident.type.upper()} - {incident.severity.upper()}
   Machine: {incident.machine_hostname or 'Unknown'}
   Process: {incident.process_name or 'N/A'}
   Details: {incident.details[:150]}{'...' if len(incident.details) > 150 else ''}
   MITRE Tags: {', '.join(incident.mitre_tags) if incident.mitre_tags else 'None'}
"""
        
        prompt += f"""

OSINT ALERTS (Last 24 Hours - Total: {len(osint_alerts)}):
"""
        
        for i, alert in enumerate(osint_alerts[:3], 1):
            prompt += f"""
{i}. {alert.source.upper()} - {alert.severity.upper()}
   Indicator: {alert.indicator}
   Type: {alert.type}
   Description: {alert.description[:150]}{'...' if len(alert.description) > 150 else ''}
"""
        
        prompt += """

TASK: Generate a concise 200-word morning brief covering:

1. TOP GLOBAL THREATS: Summarize the most critical CVEs and their potential impact
2. ACTIVE ENDPOINT INCIDENTS: Highlight any concerning patterns or high-severity incidents
3. PATTERNS NOTICED: Identify any trends, correlations, or unusual activity across sources
4. THREE IMMEDIATE ACTIONS: Provide specific, actionable priorities for the security team

Format your response as a professional security brief. Focus on clarity, actionable intelligence, and priority setting. Avoid technical jargon where possible.

Begin your brief with "MORNING SECURITY BRIEF - [Date]" and end with "Priority Actions:" followed by the three actions.
"""
        
        return prompt
    
    def _parse_morning_brief_response(self, response: str) -> str:
        """Parse and format the AI morning brief response"""
        # Clean up the response and ensure it's properly formatted
        brief = response.strip()
        
        # Ensure it starts with the proper header
        if not brief.startswith("MORNING SECURITY BRIEF"):
            brief = f"MORNING SECURITY BRIEF - {datetime.utcnow().strftime('%Y-%m-%d')}\n\n{brief}"
        
        return brief
    
    def _extract_structured_data(self, response: str, top_cves: List[models.CVE], 
                                active_incidents: List[models.Incident]) -> Dict[str, Any]:
        """Extract structured data from the morning brief"""
        
        # Extract top threats (simplified - in production, you'd parse the AI response more carefully)
        top_threats = []
        for cve in top_cves[:5]:
            risk_score = calculate_risk_score(
                cvss_score=cve.cvss_score,
                epss_score=cve.epss_score,
                actively_exploited=cve.actively_exploited,
                asset_affected=cve.asset_affected,
                published_date=cve.published_date
            )
            
            top_threats.append({
                "cve_id": cve.cve_id,
                "risk_score": risk_score['score'],
                "severity": risk_score['band'],
                "description": cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
            })
        
        # Extract active incidents
        active_incidents_data = []
        for incident in active_incidents[:5]:
            active_incidents_data.append({
                "id": incident.id,
                "type": incident.type,
                "severity": incident.severity,
                "machine": incident.machine_hostname,
                "status": incident.status
            })
        
        # Extract patterns (simplified pattern detection)
        patterns = self._detect_patterns(top_cves, active_incidents)
        
        # Extract immediate actions (simplified - in production, parse from AI response)
        actions = [
            {"action": "Review and patch critical CVEs with risk scores > 80", "priority": "high"},
            {"action": "Investigate high-severity incidents on critical assets", "priority": "high"},
            {"action": "Monitor for indicators of active exploitation", "priority": "medium"}
        ]
        
        return {
            "top_threats": top_threats,
            "active_incidents": active_incidents_data,
            "patterns": patterns,
            "actions": actions
        }
    
    def _detect_patterns(self, cves: List[models.CVE], incidents: List[models.Incident]) -> str:
        """Detect patterns in the threat data"""
        patterns = []
        
        # Check for exploitation patterns
        exploited_cves = [cve for cve in cves if cve.actively_exploited]
        if exploited_cves:
            patterns.append(f"{len(exploited_cves)} CVEs with active exploitation detected")
        
        # Check for incident patterns
        incident_types = {}
        for incident in incidents:
            incident_types[incident.type] = incident_types.get(incident.type, 0) + 1
        
        if incident_types:
            most_common = max(incident_types, key=incident_types.get)
            patterns.append(f"Spike in {most_common} incidents ({incident_types[most_common]} occurrences)")
        
        # Check for severity patterns
        high_severity_incidents = [i for i in incidents if i.severity in ['critical', 'high']]
        if len(high_severity_incidents) > len(incidents) * 0.5:
            patterns.append("High proportion of critical/high severity incidents")
        
        return "; ".join(patterns) if patterns else "No significant patterns detected"
    
    def _create_fallback_brief(self, db_session: Session) -> models.MorningBrief:
        """Create a fallback morning brief if AI generation fails"""
        fallback_content = f"""
MORNING SECURITY BRIEF - {datetime.utcnow().strftime('%Y-%m-%d')}

SYSTEM STATUS: Limited data available due to technical issues.

TOP GLOBAL THREATS:
- Unable to generate AI analysis at this time
- Please review the CVE dashboard manually

ACTIVE ENDPOINT INCIDENTS:
- Manual review required
- Check incidents page for latest updates

PATTERNS NOTICED:
- System experiencing technical difficulties
- Manual analysis recommended

Priority Actions:
1. Resolve system issues affecting morning brief generation
2. Perform manual threat assessment
3. Contact system administrator if issues persist
"""
        
        return models.MorningBrief(
            date=datetime.utcnow().date(),
            content=fallback_content,
            top_threats=[],
            active_incidents=[],
            patterns="System issues detected",
            actions=[
                {"action": "Resolve system issues", "priority": "high"},
                {"action": "Manual threat assessment", "priority": "medium"},
                {"action": "Contact administrator", "priority": "low"}
            ]
        )
    
    def get_latest_brief(self, db_session: Session) -> Optional[models.MorningBrief]:
        """Get the latest morning brief"""
        try:
            return db_session.query(models.MorningBrief).order_by(
                desc(models.MorningBrief.date)
            ).first()
        except Exception as e:
            logger.error(f"Failed to get latest morning brief: {str(e)}")
            return None
    
    def get_brief_by_date(self, db_session: Session, date: datetime.date) -> Optional[models.MorningBrief]:
        """Get morning brief by specific date"""
        try:
            return db_session.query(models.MorningBrief).filter(
                models.MorningBrief.date == date
            ).first()
        except Exception as e:
            logger.error(f"Failed to get morning brief for {date}: {str(e)}")
            return None

# Global service instance
_morning_brief_service = None

def get_morning_brief_service() -> MorningBriefService:
    """Get the global morning brief service instance"""
    global _morning_brief_service
    if _morning_brief_service is None:
        _morning_brief_service = MorningBriefService()
    return _morning_brief_service
