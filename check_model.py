# check_model.py
# This script directly tests your AI 'brain' (analyzer.py)

# We import the main function from your analyzer script
from analyzer import scamshield_analyze
import time

print("--- Starting AI Logic Test ---")

# --- Define Your Test Cases ---

test_messages = {
    "Safe": "Hey, are we still on for the meeting tomorrow at 10?",
    
    "Marketing (Suspicious)": "Congratulations! You have won a free gift. Click to claim!",
    
    "Urgent Phishing (Scam)": "URGENT: Your account is locked. You must verify your password immediately to avoid suspension.",
    
    "Credential Theft (Scam)": "Your password for microsft has expired. Please log in at http://login-microsft.com to update it.",
    
    "ML-based Spam": "viagra free delivery cheap meds special offer today only",
    
    "Link-based Scam": "Here is the document you requested: http://wmt-malware-site-test.com"
}

# --- Run the Tests ---

for label, message in test_messages.items():
    print("="*50)
    print(f"TESTING: {label}")
    print(f"INPUT:   {message[:70]}...")
    
    # This is where we call your AI function directly
    start_time = time.time()
    classification, reason = scamshield_analyze(message)
    end_time = time.time()
    
    print("\n--- RESULT ---")
    print(f"Classification: {classification}")
    print(f"Reason (Label): {reason}")
    print(f"Time Taken:     {end_time - start_time:.4f} seconds")
    print("="*50 + "\n")

print("--- Test Complete ---")