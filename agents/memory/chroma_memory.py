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

class ChromaMemoryManager:
    """Manages interactions with an ephemeral memory store to persist and retrieve agent conversations."""
    
    _memory_store = {}
    
    def __init__(self, collection_name: str = "agent_memory"):
        # ChromaDB was causing fatal C++ segmentation faults on Windows. 
        # Since this memory is already ephemeral, we use a pure Python dict.
        pass

    def save_memory(self, session_id: str, text: str) -> None:
        """Save a memory fragment."""
        if session_id not in self._memory_store:
            self._memory_store[session_id] = []
        self._memory_store[session_id].append(text)
        logger.info("memory_saved", session_id=session_id, doc_id="in-memory")

    def retrieve_memory(self, session_id: str, query: str, k: int = 3) -> list[str]:
        """Retrieve relevant past memory fragments for a given query."""
        docs = self._memory_store.get(session_id, [])
        # Return the most recent k memories (simple retrieval)
        retrieved = docs[-k:] if docs else []
        
        logger.info("memory_retrieved", session_id=session_id, query=query, retrieved_count=len(retrieved))
        return retrieved


