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
    """Manages interactions with ChromaDB to persist and retrieve agent conversations."""
    
    def __init__(self, collection_name: str = "agent_memory"):
        self.host = os.getenv("CHROMA_HOST", "localhost")
        self.port = os.getenv("CHROMA_PORT", "8000")
        
        try:
            # We attempt to connect using the HTTP client
            self.client = chromadb.HttpClient(
                host=self.host, 
                port=self.port,
                settings=Settings(anonymized_telemetry=False)
            )
            # Embedding function via OpenAI
            self.embedding_function = OpenAIEmbeddings()
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(name=collection_name)
            logger.info("chromadb_connected", host=self.host, port=self.port, collection=collection_name)
        except Exception as e:
            logger.warning("chromadb_connection_failed", error=str(e), fallback="EphemeralClient")
            # Fallback to an ephemeral client for testing purposes if the HTTP server is unavailable
            self.client = chromadb.EphemeralClient()
            self.embedding_function = OpenAIEmbeddings()
            self.collection = self.client.get_or_create_collection(name=collection_name)

    def save_memory(self, session_id: str, text: str) -> None:
        """Save a memory fragment to ChromaDB."""
        doc_id = str(uuid.uuid4())
        
        # Get embeddings
        embeddings = self.embedding_function.embed_query(text)
        
        self.collection.add(
            ids=[doc_id],
            embeddings=[embeddings],
            documents=[text],
            metadatas=[{"session_id": session_id}]
        )
        logger.info("memory_saved", session_id=session_id, doc_id=doc_id)

    def retrieve_memory(self, session_id: str, query: str, k: int = 3) -> list[str]:
        """Retrieve relevant past memory fragments for a given query."""
        # Get embeddings for the query
        query_embeddings = self.embedding_function.embed_query(query)
        
        results = self.collection.query(
            query_embeddings=[query_embeddings],
            n_results=k,
            where={"session_id": session_id}
        )
        
        docs = results.get("documents", [[]])[0]
        logger.info("memory_retrieved", session_id=session_id, query=query, retrieved_count=len(docs))
        return docs
