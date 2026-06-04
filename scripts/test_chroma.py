import sys, os
sys.path.insert(0, os.path.dirname(__file__) + '/..')
import dotenv
dotenv.load_dotenv()
from agents.memory.chroma_memory import ChromaMemoryManager

m = ChromaMemoryManager()
m.save_memory("test_session", "hello")
print("Saved")
m.retrieve_memory("test_session", "hello")
print("SUCCESS!")
