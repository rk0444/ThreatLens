import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
import json

logger = logging.getLogger(__name__)

class ThreatVectorStore:
    """ChromaDB vector store for threat intelligence and incidents"""
    
    def __init__(self, persist_directory: str = None):
        if persist_directory is None:
            persist_directory = os.getenv("CHROMA_PERSIST_DIRECTORY", "./backend/database/chroma")
        
        # Ensure persist directory exists
        os.makedirs(persist_directory, exist_ok=True)
        
        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Initialize embedding function
        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()
        
        # Get or create collections
        self.threats_collection = self._get_or_create_collection(
            os.getenv("CHROMA_COLLECTION_THREATS", "threat_intelligence"),
            "Threat intelligence including CVEs and OSINT alerts"
        )
        
        self.incidents_collection = self._get_or_create_collection(
            os.getenv("CHROMA_COLLECTION_INCIDENTS", "incidents"),
            "Security incidents and endpoint detections"
        )
        
        logger.info("Vector store initialized successfully")
    
    def _get_or_create_collection(self, name: str, description: str):
        """Get or create a ChromaDB collection"""
        try:
            collection = self.client.get_collection(name)
            logger.info(f"Collection '{name}' loaded successfully")
        except Exception:
            collection = self.client.create_collection(
                name=name,
                metadata={"description": description},
                embedding_function=self.embedding_function
            )
            logger.info(f"Collection '{name}' created successfully")
        
        return collection
    
    def add_threat(self, threat_id: str, content: str, metadata: Dict[str, Any]):
        """Add a threat to the threat intelligence collection"""
        try:
            # Prepare metadata
            doc_metadata = {
                "threat_id": threat_id,
                "type": metadata.get("type", "unknown"),
                "severity": metadata.get("severity", "unknown"),
                "created_at": datetime.utcnow().isoformat(),
                **metadata
            }
            
            self.threats_collection.add(
                documents=[content],
                metadatas=[doc_metadata],
                ids=[threat_id]
            )
            
            logger.info(f"Added threat {threat_id} to vector store")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add threat {threat_id}: {str(e)}")
            return False
    
    def add_incident(self, incident_id: str, content: str, metadata: Dict[str, Any]):
        """Add an incident to the incidents collection"""
        try:
            # Prepare metadata
            doc_metadata = {
                "incident_id": incident_id,
                "type": "incident",
                "severity": metadata.get("severity", "unknown"),
                "machine_id": metadata.get("machine_id"),
                "created_at": datetime.utcnow().isoformat(),
                **metadata
            }
            
            self.incidents_collection.add(
                documents=[content],
                metadatas=[doc_metadata],
                ids=[incident_id]
            )
            
            logger.info(f"Added incident {incident_id} to vector store")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add incident {incident_id}: {str(e)}")
            return False
    
    def search_similar_threats(self, query: str, n_results: int = 5, 
                              threat_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for similar threats in the threat intelligence collection"""
        try:
            # Build where clause for filtering by type if specified
            where_clause = None
            if threat_type:
                where_clause = {"type": threat_type}
            
            results = self.threats_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause,
                include=["documents", "metadatas", "distances"]
            )
            
            # Format results
            formatted_results = []
            for i in range(len(results["ids"][0])):
                formatted_results.append({
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "similarity_score": 1 - results["distances"][0][i]  # Convert distance to similarity
                })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Failed to search similar threats: {str(e)}")
            return []
    
    def search_similar_incidents(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for similar incidents in the incidents collection"""
        try:
            results = self.incidents_collection.query(
                query_texts=[query],
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
            
            # Format results
            formatted_results = []
            for i in range(len(results["ids"][0])):
                formatted_results.append({
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "similarity_score": 1 - results["distances"][0][i]  # Convert distance to similarity
                })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Failed to search similar incidents: {str(e)}")
            return []
    
    def cross_search(self, query: str, n_results: int = 3) -> Dict[str, List[Dict[str, Any]]]:
        """Search across both threat intelligence and incidents"""
        return {
            "threats": self.search_similar_threats(query, n_results),
            "incidents": self.search_similar_incidents(query, n_results)
        }
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific threat by ID"""
        try:
            results = self.threats_collection.get(
                ids=[threat_id],
                include=["documents", "metadatas"]
            )
            
            if results["ids"]:
                return {
                    "id": results["ids"][0],
                    "document": results["documents"][0],
                    "metadata": results["metadatas"][0]
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get threat {threat_id}: {str(e)}")
            return None
    
    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific incident by ID"""
        try:
            results = self.incidents_collection.get(
                ids=[incident_id],
                include=["documents", "metadatas"]
            )
            
            if results["ids"]:
                return {
                    "id": results["ids"][0],
                    "document": results["documents"][0],
                    "metadata": results["metadatas"][0]
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get incident {incident_id}: {str(e)}")
            return None
    
    def update_threat(self, threat_id: str, content: str = None, metadata: Dict[str, Any] = None):
        """Update an existing threat"""
        try:
            # Get existing threat
            existing = self.get_threat_by_id(threat_id)
            if not existing:
                return False
            
            # Prepare update data
            update_content = content if content is not None else existing["document"]
            update_metadata = existing["metadata"]
            if metadata:
                update_metadata.update(metadata)
            update_metadata["updated_at"] = datetime.utcnow().isoformat()
            
            # Delete and re-add (ChromaDB doesn't have direct update)
            self.threats_collection.delete(ids=[threat_id])
            self.threats_collection.add(
                documents=[update_content],
                metadatas=[update_metadata],
                ids=[threat_id]
            )
            
            logger.info(f"Updated threat {threat_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update threat {threat_id}: {str(e)}")
            return False
    
    def delete_threat(self, threat_id: str):
        """Delete a threat from the vector store"""
        try:
            self.threats_collection.delete(ids=[threat_id])
            logger.info(f"Deleted threat {threat_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete threat {threat_id}: {str(e)}")
            return False
    
    def get_collection_stats(self) -> Dict[str, int]:
        """Get statistics about the collections"""
        try:
            threat_count = self.threats_collection.count()
            incident_count = self.incidents_collection.count()
            
            return {
                "threats": threat_count,
                "incidents": incident_count,
                "total": threat_count + incident_count
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {str(e)}")
            return {"threats": 0, "incidents": 0, "total": 0}

# Global vector store instance
_vector_store = None

def get_vector_store() -> ThreatVectorStore:
    """Get the global vector store instance"""
    global _vector_store
    if _vector_store is None:
        _vector_store = ThreatVectorStore()
    return _vector_store
