# demo.py

import requests
import json
import time

# !!! IMPORTANT !!!
# AFTER YOU DEPLOY, CHANGE THIS URL TO YOUR LIVE PYTHONANYWHERE URL
CLOUD_API_URL = "http://127.0.0.1:5000/api/analyze"


# --- DEFINE YOUR DEMO MESSAGES ---

email_1_safe = {
    "subject": "Meeting Reminder",
    "body": "Hey team, just a reminder that we have our weekly sync tomorrow at 10 AM. Please bring your updates. -Bob"
}

email_2_urgent_scam = {
    "subject": "URGENT: Action Required!",
    "body": "Your account has been locked due to a security breach. You must verify your password immediately to avoid suspension. Click here to verify: http://bit.ly/fake-bank-link"
}

email_3_marketing = {
    "subject": "You are a winner!",
    "body": "Congratulations! You have won a free gift. Click here to claim your prize now: http://prizelink.xyz"
}

email_4_credential_scam = {
    "subject": "Password Reset",
    "body": "Someone tried to access your account. Please verify your password at http://login-microsft.com to secure your account."
}

email_5_link_scam = {
    "subject": "Download your file",
    "body": "Here is the document you requested. Please download it from http://wmt-malware-site-test.com"
}


def check_email(email):
    """
    Sends the email body to your cloud API and prints the verdict.
    """
    print("="*50)
    print(f"New Email Received: '{email['subject']}'")
    print("--- Sending to ScamShield AI Cloud API ---")
    time.sleep(1) # Dramatic pause
    
    try:
        headers = {'Content-Type': 'application/json'}
        payload = json.dumps({'message': email['body']})
        
        response = requests.post(CLOUD_API_URL, data=payload, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            classification = result.get('classification')
            reason = result.get('reason_label')
            
            print(f"\nAPI VERDICT: [{classification}]")
            print(f"REASON: {reason}\n")
            
        else:
            print(f"\n--- ERROR FROM CLOUD API ---")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}\n")
            
    except requests.exceptions.RequestException as e:
        print("\n--- CRITICAL CLIENT ERROR ---")
        print(f"Could not connect to API at {CLOUD_API_URL}")
        print("Is the server running? Is the URL correct?\n")

# --- RUN THE DEMO ---
print(f"Connecting to ScamShield AI at: {CLOUD_API_URL}\n")
check_email(email_1_safe)
check_email(email_3_marketing)
check_email(email_2_urgent_scam)
check_email(email_4_credential_scam)
check_email(email_5_link_scam) # This one tests the VirusTotal link check