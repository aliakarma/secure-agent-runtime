import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (where this script lives)
load_dotenv()
load_dotenv(Path(__file__).resolve().parent / ".env")

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    print("ERROR: OPENAI_API_KEY not found in environment. Please make sure you saved the .env file!")
else:
    print(f"SUCCESS: OPENAI_API_KEY loaded successfully: {api_key[:8]}...{api_key[-4:]}")
    
    from agents.workflow import run_travel_graph
    
    print("\nExecuting Phase 2 Travel Graph...")
    try:
        result = run_travel_graph("Book me a flight to Riyadh and a hotel in Riyadh")
        
        print("\n--- Execution Result ---")
        for msg in result.get("messages", []):
            name = getattr(msg, 'name', '') or type(msg).__name__
            print(f"[{name}] {msg.content}")
            
        print("\nSUCCESS: Execution completed successfully!")
    except Exception as e:
        print(f"\nERROR: Execution failed: {e}")
