import os
import logging
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from langchain_core.messages import HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from typing_extensions import Annotated, TypedDict

from ..database.threat_schema import (
    ThreatSchema, ThreatType, SeverityLevel, MITREStage,
    AssetContext, CorrelationInfo, AnalystSummary, ThreatProcessingResult
)
from ..database import models
from .vector_store import get_vector_store
from .scoring import calculate_risk_score

logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    """State for the LangGraph pipeline"""
    messages: Annotated[list, add_messages]
    raw_data: Dict[str, Any]
    threat_type: ThreatType
    threat_schema: Optional[ThreatSchema]
    correlation_info: Optional[CorrelationInfo]
    asset_context: Optional[AssetContext]
    processing_result: ThreatProcessingResult
    error_message: Optional[str]

class MultiAgentPipeline:
    """LangGraph multi-agent pipeline for threat processing"""
    
    def __init__(self):
        # Initialize LLMs
        self.groq_llm = ChatGroq(
            model=os.getenv("GROQ_MODEL", "llama-3-70b-8192"),
            api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.1
        )
        
        self.openai_llm = ChatOpenAI(
            model=os.getenv("OPENAI_MODEL", "gpt-4o"),
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=0.3
        )
        
        # Initialize vector store
        self.vector_store = get_vector_store()
        
        # Build the graph
        self.graph = self._build_graph()
        
        logger.info("Multi-agent pipeline initialized")
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph pipeline"""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("hunter", self._hunter_agent)
        workflow.add_node("correlator", self._correlator_agent)
        workflow.add_node("context", self._context_agent)
        workflow.add_node("analyst", self._analyst_agent)
        
        # Define the flow
        workflow.set_entry_point("hunter")
        workflow.add_edge("hunter", "correlator")
        workflow.add_edge("correlator", "context")
        workflow.add_edge("context", "analyst")
        workflow.add_edge("analyst", END)
        
        return workflow.compile()
    
    async def process_threat(self, raw_data: Dict[str, Any], threat_type: ThreatType) -> ThreatProcessingResult:
        """Process a threat through the multi-agent pipeline"""
        start_time = time.time()
        
        try:
            # Initialize state
            initial_state = AgentState(
                messages=[],
                raw_data=raw_data,
                threat_type=threat_type,
                threat_schema=None,
                correlation_info=None,
                asset_context=None,
                processing_result=ThreatProcessingResult(
                    success=False,
                    threat_id=raw_data.get("id", "unknown"),
                    processing_time=0.0
                ),
                error_message=None
            )
            
            # Run the pipeline
            final_state = await self.graph.ainvoke(initial_state)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            final_state["processing_result"].processing_time = processing_time
            
            logger.info(f"Threat {final_state['processing_result'].threat_id} processed in {processing_time:.2f}s")
            
            return final_state["processing_result"]
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Pipeline failed for threat {raw_data.get('id', 'unknown')}: {str(e)}")
            
            return ThreatProcessingResult(
                success=False,
                threat_id=raw_data.get("id", "unknown"),
                processing_time=processing_time,
                error_message=str(e)
            )
    
    async def _hunter_agent(self, state: AgentState) -> AgentState:
        """NODE 1: Extract and normalize threat data"""
        try:
            logger.info(f"Hunter agent processing {state['threat_type'].value}")
            
            # Use Groq for fast processing
            if state["threat_type"] == ThreatType.CVE:
                threat_schema = await self._process_cve(state["raw_data"])
            elif state["threat_type"] == ThreatType.INCIDENT:
                threat_schema = await self._process_incident(state["raw_data"])
            elif state["threat_type"] == ThreatType.OSINT:
                threat_schema = await self._process_osint(state["raw_data"])
            else:
                raise ValueError(f"Unsupported threat type: {state['threat_type']}")
            
            state["threat_schema"] = threat_schema
            state["processing_result"].hunter_result = {"success": True, "threat_id": threat_schema.threat_id}
            
            logger.info(f"Hunter agent completed for {threat_schema.threat_id}")
            
        except Exception as e:
            logger.error(f"Hunter agent failed: {str(e)}")
            state["error_message"] = f"Hunter agent failed: {str(e)}"
            state["processing_result"].hunter_result = {"success": False, "error": str(e)}
        
        return state
    
    async def _correlator_agent(self, state: AgentState) -> AgentState:
        """NODE 2: Find correlations using vector similarity"""
        try:
            if not state["threat_schema"]:
                raise ValueError("No threat schema available from hunter agent")
            
            logger.info(f"Correlator agent processing {state['threat_schema'].threat_id}")
            
            # Create search query from threat description
            search_query = f"{state['threat_schema'].title} {state['threat_schema'].description}"
            
            # Search for related threats and incidents
            similar_threats = self.vector_store.search_similar_threats(search_query, n_results=5)
            similar_incidents = self.vector_store.search_similar_incidents(search_query, n_results=3)
            
            # Build correlation info
            correlation_info = CorrelationInfo(
                correlated_threats=[t["id"] for t in similar_threats],
                related_incidents=[int(t["metadata"].get("incident_id", 0)) for t in similar_incidents if t["metadata"].get("incident_id")]
            )
            
            # Check for CVE-incident correlations
            if state["threat_type"] == ThreatType.CVE and similar_incidents:
                # Look for high similarity matches that might indicate active exploitation
                high_similarity_incidents = [i for i in similar_incidents if i["similarity_score"] > 0.8]
                if high_similarity_incidents:
                    incident = high_similarity_incidents[0]
                    machine_hostname = incident["metadata"].get("machine_hostname", "unknown machine")
                    correlation_info.correlation_statement = (
                        f"The behaviour on {machine_hostname} matches the exploitation pattern of {state['threat_schema'].cve_id}"
                    )
                    correlation_info.correlation_score = incident["similarity_score"]
                    correlation_info.related_cves = [state['threat_schema'].cve_id]
            
            elif state["threat_type"] == ThreatType.INCIDENT and similar_threats:
                # Look for CVEs that might explain this incident
                high_similarity_cves = [t for t in similar_threats if t["similarity_score"] > 0.8 and t["metadata"].get("type") == "cve"]
                if high_similarity_cves:
                    cve = high_similarity_cves[0]
                    correlation_info.correlation_statement = (
                        f"The incident on {state['threat_schema'].machine_hostname} appears related to {cve['metadata'].get('cve_id', 'CVE-unknown')}"
                    )
                    correlation_info.correlation_score = cve["similarity_score"]
                    correlation_info.related_cves = [cve["metadata"].get("cve_id", "CVE-unknown")]
            
            state["correlation_info"] = correlation_info
            state["processing_result"].correlator_result = {
                "success": True,
                "correlations_found": len(correlation_info.correlated_threats) + len(correlation_info.related_incidents),
                "correlation_statement": correlation_info.correlation_statement
            }
            
            logger.info(f"Correlator agent completed for {state['threat_schema'].threat_id}")
            
        except Exception as e:
            logger.error(f"Correlator agent failed: {str(e)}")
            state["error_message"] = f"Correlator agent failed: {str(e)}"
            state["processing_result"].correlator_result = {"success": False, "error": str(e)}
        
        return state
    
    async def _context_agent(self, state: AgentState) -> AgentState:
        """NODE 3: Enrich with asset context"""
        try:
            if not state["threat_schema"]:
                raise ValueError("No threat schema available")
            
            logger.info(f"Context agent processing {state['threat_schema'].threat_id}")
            
            asset_context = AssetContext()
            
            # For CVEs, check which assets are affected
            if state["threat_type"] == ThreatType.CVE:
                affected_products = state["threat_schema"].affected_products or []
                
                # This would typically query the database for matching assets
                # For now, we'll simulate this logic
                if affected_products:
                    asset_context.is_affected = True
                    asset_context.vulnerability_count = len(affected_products)
                    # In a real implementation, you'd query the assets table
                    # asset_context.asset_name = "Found Asset"
                    # asset_context.asset_ip = "192.168.1.100"
                    # asset_context.asset_os = "Windows 10"
            
            # For incidents, get asset details
            elif state["threat_type"] == ThreatType.INCIDENT:
                if state["threat_schema"].machine_id:
                    asset_context.asset_id = state["threat_schema"].machine_id
                    asset_context.asset_name = state["threat_schema"].machine_hostname
                    asset_context.is_affected = True
                    asset_context.vulnerability_count = 1
            
            state["asset_context"] = asset_context
            state["processing_result"].context_result = {"success": True, "assets_affected": asset_context.is_affected}
            
            logger.info(f"Context agent completed for {state['threat_schema'].threat_id}")
            
        except Exception as e:
            logger.error(f"Context agent failed: {str(e)}")
            state["error_message"] = f"Context agent failed: {str(e)}"
            state["processing_result"].context_result = {"success": False, "error": str(e)}
        
        return state
    
    async def _analyst_agent(self, state: AgentState) -> AgentState:
        """NODE 4: Generate analyst summary and MITRE tags using GPT-4o"""
        try:
            if not state["threat_schema"]:
                raise ValueError("No threat schema available")
            
            logger.info(f"Analyst agent processing {state['threat_schema'].threat_id}")
            
            # Build the prompt for the analyst
            prompt = self._build_analyst_prompt(state)
            
            # Use GPT-4o for high-quality analysis
            response = await self.openai_llm.ainvoke([
                HumanMessage(content=prompt)
            ])
            
            # Parse the response
            analysis = self._parse_analyst_response(response.content)
            
            # Create analyst summary
            analyst_summary = AnalystSummary(
                what_is_affected=analysis.get("what_is_affected", "Unknown"),
                how_it_works=analysis.get("how_it_works", "Unknown"),
                what_to_do_now=analysis.get("what_to_do_now", "Contact security team"),
                confidence_score=analysis.get("confidence", 0.7),
                generated_at=datetime.utcnow()
            )
            
            # Update threat schema
            state["threat_schema"].analyst_summary = analyst_summary
            state["threat_schema"].mitre_stage = analysis.get("mitre_stage")
            state["threat_schema"].mitre_tags = analysis.get("mitre_tags", [])
            
            state["processing_result"].analyst_result = {
                "success": True,
                "mitre_stage": analysis.get("mitre_stage"),
                "mitre_tags": analysis.get("mitre_tags", []),
                "confidence": analysis.get("confidence", 0.7)
            }
            
            state["processing_result"].success = True
            
            logger.info(f"Analyst agent completed for {state['threat_schema'].threat_id}")
            
        except Exception as e:
            logger.error(f"Analyst agent failed: {str(e)}")
            state["error_message"] = f"Analyst agent failed: {str(e)}"
            state["processing_result"].analyst_result = {"success": False, "error": str(e)}
        
        return state
    
    def _build_analyst_prompt(self, state: AgentState) -> str:
        """Build the analyst prompt"""
        threat = state["threat_schema"]
        
        prompt = f"""
You are a cybersecurity analyst. Analyze this threat and provide a clear summary.

THREAT DETAILS:
Type: {threat.threat_type.value}
Title: {threat.title}
Description: {threat.description}
Severity: {threat.severity.value}
"""
        
        if threat.cve_id:
            prompt += f"CVE ID: {threat.cve_id}\n"
            prompt += f"CVSS Score: {threat.cvss_score}\n"
            prompt += f"Actively Exploited: {threat.actively_exploited}\n"
        
        if threat.machine_hostname:
            prompt += f"Affected Machine: {threat.machine_hostname}\n"
            prompt += f"Process: {threat.process_name}\n"
            prompt += f"File Path: {threat.file_path}\n"
        
        if state["correlation_info"] and state["correlation_info"].correlation_statement:
            prompt += f"\nCORRELATION: {state['correlation_info'].correlation_statement}\n"
        
        if state["asset_context"] and state["asset_context"].is_affected:
            prompt += f"\nASSET CONTEXT: {state['asset_context'].vulnerability_count} assets potentially affected\n"
        
        prompt += """

Provide your analysis in the following JSON format:
{
    "what_is_affected": "Clear description of what systems, data, or assets are affected",
    "how_it_works": "Technical explanation of how the threat operates in simple terms",
    "what_to_do_now": "Immediate actionable steps for containment and remediation",
    "mitre_stage": "One of: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact",
    "mitre_tags": ["tag1", "tag2", "tag3"],
    "confidence": 0.8
}

Focus on clarity and actionable intelligence. Avoid jargon where possible.
"""
        
        return prompt
    
    def _parse_analyst_response(self, response: str) -> Dict[str, Any]:
        """Parse the analyst response"""
        try:
            # Try to extract JSON from the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback if JSON parsing fails
        return {
            "what_is_affected": "Analysis unavailable",
            "how_it_works": "Analysis unavailable", 
            "what_to_do_now": "Contact security team immediately",
            "mitre_stage": None,
            "mitre_tags": [],
            "confidence": 0.3
        }
    
    async def _process_cve(self, raw_data: Dict[str, Any]) -> ThreatSchema:
        """Process CVE data into ThreatSchema"""
        prompt = f"""
Extract and normalize this CVE data into a structured format:

CVE DATA:
{json.dumps(raw_data, indent=2)}

Focus on:
- Extracting key fields (CVE ID, description, CVSS, affected products)
- Normalizing severity levels
- Identifying exploitation status
- Determining MITRE ATT&CK stage

Return a JSON object with the extracted information.
"""
        
        response = await self.groq_llm.ainvoke([HumanMessage(content=prompt)])
        
        # Parse the response and create ThreatSchema
        try:
            extracted = json.loads(response.content)
        except:
            # Fallback to manual extraction
            extracted = self._extract_cve_manually(raw_data)
        
        return ThreatSchema(
            threat_id=raw_data.get("cve_id", f"cve-{raw_data.get('id', 'unknown')}"),
            threat_type=ThreatType.CVE,
            title=extracted.get("title", raw_data.get("cve_id", "Unknown CVE")),
            description=extracted.get("description", raw_data.get("description", "")),
            severity=SeverityLevel(extracted.get("severity", "medium")),
            cve_id=raw_data.get("cve_id"),
            cvss_score=raw_data.get("cvss_score"),
            epss_score=raw_data.get("epss_score"),
            affected_products=raw_data.get("affected_products", []),
            actively_exploited=raw_data.get("actively_exploited", False),
            ransomware_use=raw_data.get("ransomware_use", False),
            published_date=raw_data.get("published_date"),
            raw_data=raw_data
        )
    
    async def _process_incident(self, raw_data: Dict[str, Any]) -> ThreatSchema:
        """Process incident data into ThreatSchema"""
        return ThreatSchema(
            threat_id=f"incident-{raw_data.get('id', 'unknown')}",
            threat_type=ThreatType.INCIDENT,
            title=raw_data.get("type", "Security Incident"),
            description=raw_data.get("details", raw_data.get("description", "")),
            severity=SeverityLevel(raw_data.get("severity", "medium")),
            machine_id=raw_data.get("machine_id"),
            machine_hostname=raw_data.get("machine_hostname"),
            process_name=raw_data.get("process_name"),
            file_path=raw_data.get("file_path"),
            network_connection=raw_data.get("network_connection"),
            sandbox_verdict=raw_data.get("sandbox_verdict"),
            virustotal_result=raw_data.get("virustotal_result"),
            published_date=raw_data.get("created_at"),
            raw_data=raw_data
        )
    
    async def _process_osint(self, raw_data: Dict[str, Any]) -> ThreatSchema:
        """Process OSINT data into ThreatSchema"""
        return ThreatSchema(
            threat_id=f"osint-{raw_data.get('id', 'unknown')}",
            threat_type=ThreatType.OSINT,
            title=raw_data.get("indicator", "OSINT Alert"),
            description=raw_data.get("description", ""),
            severity=SeverityLevel(raw_data.get("severity", "medium")),
            source=raw_data.get("source"),
            indicator=raw_data.get("indicator"),
            indicator_type=raw_data.get("type"),
            published_date=raw_data.get("created_at"),
            raw_data=raw_data
        )
    
    def _extract_cve_manually(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Manual CVE extraction fallback"""
        cvss = raw_data.get("cvss_score", 0)
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0:
            severity = "high"
        elif cvss >= 4.0:
            severity = "medium"
        else:
            severity = "low"
        
        return {
            "title": raw_data.get("cve_id", "Unknown CVE"),
            "description": raw_data.get("description", ""),
            "severity": severity
        }

# Global pipeline instance
_pipeline = None

def get_pipeline() -> MultiAgentPipeline:
    """Get the global multi-agent pipeline instance"""
    global _pipeline
    if _pipeline is None:
        _pipeline = MultiAgentPipeline()
    return _pipeline
