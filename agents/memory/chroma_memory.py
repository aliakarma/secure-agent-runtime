"""
ChromaDB integration for persistent agent memory.
"""

import os
import chromadb
from chromadb.config import Settings
from langchain_openai import OpenAIEmbeddings
import uuid
import sys
from pathlib import Path

# Add project root to path for structured logging if needed
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from logging_config import get_logger

logger = get_logger(__name__)

import numpy as np

class ChromaMemoryManager:
    """Manages interactions with an ephemeral memory store to persist and retrieve agent conversations using vector search."""
    
    # Structure: session_id -> list of {"text": str, "embedding": list[float]}
    _memory_store = {}
    
    def __init__(self, collection_name: str = "agent_memory"):
        # We use OpenAIEmbeddings for genuine vector store memory search, falling back gracefully
        self.embeddings = OpenAIEmbeddings(timeout=15)

    def save_memory(self, session_id: str, text: str) -> None:
        """Save a memory fragment with its vector embedding."""
        if session_id not in self._memory_store:
            self._memory_store[session_id] = []
            
        try:
            embedding = self.embeddings.embed_query(text)
        except Exception as e:
            logger.error(f"Failed to generate embedding for memory: {e}. Saving without embedding.")
            embedding = None
            
        self._memory_store[session_id].append({
            "text": text,
            "embedding": embedding
        })
        logger.info("memory_saved", session_id=session_id, doc_id="in-memory-vector")

    def retrieve_memory(self, session_id: str, query: str, k: int = 3) -> list[str]:
        """Retrieve relevant past memory fragments for a given query using cosine similarity."""
        docs = self._memory_store.get(session_id, [])
        if not docs:
            logger.info("memory_retrieved", session_id=session_id, query=query, retrieved_count=0)
            return []
            
        # Try to retrieve via cosine similarity if we have query and document embeddings
        try:
            query_embedding = self.embeddings.embed_query(query)
            query_vector = np.array(query_embedding)
            
            scored_docs = []
            for doc in docs:
                if doc.get("embedding") is not None:
                    doc_vector = np.array(doc["embedding"])
                    # Cosine similarity formula: (A . B) / (||A|| * ||B||)
                    dot_product = np.dot(query_vector, doc_vector)
                    norm_a = np.linalg.norm(query_vector)
                    norm_b = np.linalg.norm(doc_vector)
                    
                    if norm_a > 0 and norm_b > 0:
                        similarity = dot_product / (norm_a * norm_b)
                    else:
                        similarity = 0.0
                else:
                    similarity = 0.0 # fallback
                scored_docs.append((similarity, doc["text"]))
                
            # Sort by similarity descending
            scored_docs.sort(key=lambda x: x[0], reverse=True)
            retrieved = [text for score, text in scored_docs[:k]]
        except Exception as e:
            logger.error(f"Failed vector search retrieval: {e}. Falling back to most recent k items.")
            # Fallback to simple chronological retrieval
            retrieved = [doc["text"] for doc in docs[-k:] if "text" in doc]
            
        logger.info("memory_retrieved", session_id=session_id, query=query, retrieved_count=len(retrieved))
        return retrieved


