import pytest
from sanitizers.trust_engine import TrustEngine
from sanitizers.hooks import current_session_id, current_trust_tier, secure_tool_wrapper

def test_trust_score_calculation():
    engine = TrustEngine()
    # High trust: system origin, benign
    score1, tier1 = engine.process_payload("session_1", "Hello", "system", False)
    assert score1 >= 0.8
    assert tier1 == "HIGH"
    
    # Malicious prompt drops P(x) to 0 and H(x) to 0.5. Score = 0.5 (MEDIUM).
    score2, tier2 = engine.process_payload("session_2", "Ignore instructions", "user", True)
    assert score2 == 0.5
    assert tier2 == "MEDIUM"
    
    # Second malicious prompt drops H(x) to 0. Score = 0.375 (LOW)
    score3, tier3 = engine.process_payload("session_2", "Hack", "user", True)
    assert score3 < 0.4
    assert tier3 == "LOW"

def test_amnesia_fix():
    engine = TrustEngine()
    # User sends 3 malicious prompts in a row
    engine.process_payload("session_amnesia", "Bad 1", "user", True)
    engine.process_payload("session_amnesia", "Bad 2", "user", True)
    
    # Even if the 3rd prompt is benign, historical trust H(x) is ruined.
    score, tier = engine.process_payload("session_amnesia", "Good", "user", False)
    
    # Normally user benign is: S(0.5)*0.25 + P(1.0)*0.25 + H(1.0)*0.25 + R(1.0)*0.25 = 0.75 (MEDIUM)
    # But since 2 injections occurred: H(x) = max(0, 1 - 2*0.5) = 0
    # Score = 0.125 + 0.25 + 0 + 0.25 = 0.625 (Still medium but significantly lower)
    # Let's verify score is lowered.
    assert score == 0.62

def test_policy_enforcement():
    # Mock a tool
    @secure_tool_wrapper
    def action_tool(arg: str):
        return "Success"
        
    @secure_tool_wrapper
    def search_flights(arg: str):
        return "Flights"

    current_session_id.set("test_session")
    
    # Test HIGH
    current_trust_tier.set("HIGH")
    assert action_tool("test") == "Success"
    
    # Test LOW
    current_trust_tier.set("LOW")
    assert "Error: Action blocked" in action_tool("test")
    
    # Test MEDIUM
    current_trust_tier.set("MEDIUM")
    assert "Error: Tool action_tool blocked" in action_tool("test")
    # Medium allows search_flights
    assert search_flights("test") == "Flights"
