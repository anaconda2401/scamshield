# analyzer.py

import joblib
import re
import time
import requests
import json
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from experta import *
from config import VT_API_KEY # Import your secret key

# --- 1. LOAD YOUR AI MODELS (Loads once when server starts) ---
print("Loading AI models (vectorizer.pkl, model.pkl)...")
try:
    vectorizer = joblib.load('vectorizer.pkl')
    ml_model = joblib.load('model.pkl')
    print("AI models loaded successfully.")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load .pkl models: {e}")
    vectorizer, ml_model = None, None

# --- 2. SETUP PREPROCESSING (Loads once when server starts) ---
lemmatizer = WordNetLemmatizer()
stop_words = set(stopwords.words('english'))

def preprocess(message):
    message = str(message).lower()
    message = re.sub(r'http[s]?://\S+', '_URL_', message)
    message = re.sub(r'\d+', '_NUM_', message)
    message = re.sub(r'[^a-z\s_]', '', message)
    tokens = message.split()
    tokens = [lemmatizer.lemmatize(w) for w in tokens if w not in stop_words]
    return ' '.join(tokens)

# --- 3. CLOUD LINK CHECKER FUNCTION ---
def check_virustotal_link(text):
    """
    Finds the first URL and checks it with the VirusTotal cloud service.
    """
    urls = re.findall(r'http[s]?://\S+', text)
    if not urls:
        return (False, "No URL found") # No URL to check

    url_to_check = urls[0] # Check the first URL
    
    report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VT_API_KEY, 'resource': url_to_check}
    
    try:
        response = requests.get(report_url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                if positives > 2: # If 3 or more security vendors flag it
                    return (True, f"Malicious URL Flagged by Cloud API ({positives} vendors)")
                else:
                    return (False, "URL confirmed as safe by Cloud API")
            else:
                return (False, "URL not yet scanned by Cloud API")
    except requests.exceptions.RequestException as e:
        print(f"Error calling VirusTotal API: {e}")
        return (False, "Cloud API error") # Fail safe

    return (False, "URL check inconclusive")

# --- 4. EXPERT SYSTEM RULES (Your "Labels") ---
class Message(Fact):
    pass

class ScamShieldEngine(KnowledgeEngine):
    def __init__(self):
        super().__init__()
        self.risk_score = 0.0
        self.explanations = [] # This will hold our "labels"

    @Rule(Message(text=MATCH.text),
          TEST(lambda text: "urgent" in text and "verify" in text))
    def rule_urgent_verify(self):
        self.risk_score += 0.9
        self.explanations.append("Label: Urgent Credential Theft")

    @Rule(Message(text=MATCH.text),
          TEST(lambda text: "password" in text and "http" in text))
    def rule_password_link(self):
        self.risk_score += 1.0 # Max risk
        self.explanations.append("Label: Credential Theft (Password Request)")

    @Rule(Message(text=MATCH.text),
          TEST(lambda text: "free gift" in text or "you have won" in text or "winner" in text))
    def rule_marketing(self):
        self.risk_score += 0.4
        self.explanations.append("Label: Suspicious (Marketing/Spam)")
    
    @Rule(Message(text=MATCH.text),
          TEST(lambda text: "urgent" in text and "action required" in text))
    def rule_urgent_action(self):
        self.risk_score += 0.7
        self.explanations.append("Label: Urgent Phishing Attempt")

    def get_results(self):
        if self.risk_score > 1.0: self.risk_score = 1.0
        return self.risk_score, " | ".join(self.explanations)

# --- 5. THE MAIN CLASSIFICATION FUNCTION (IMPROVED) ---
def scamshield_analyze(message):
    
    # 1. Cloud Link Check (Fast Override)
    (is_malicious, cloud_reason) = check_virustotal_link(message)
    if is_malicious:
        return "Scam Likely", cloud_reason
    
    # 2. Preprocess message for local AI
    processed_message = preprocess(message)
    
    # 3. Rule-based reasoning
    engine = ScamShieldEngine()
    engine.reset()
    engine.declare(Message(text=processed_message))
    engine.run()
    rule_score, rule_explanation = engine.get_results()
    
    # 4. ML prediction (from SpamAssasin)
    if ml_model and vectorizer:
        try:
            vectorized_text = vectorizer.transform([processed_message])
            prob_score = ml_model.predict_proba(vectorized_text)[0][1] # Prob of 'scam'
        except Exception as e:
            print(f"Error during ML prediction: {e}")
            prob_score = 0.0
    else:
        prob_score = 0.0 # Fail safe
     
    # 5. Weighted Fusion (Hybrid Score)
    final_score = (0.6 * rule_score) + (0.4 * prob_score)
    
    # 6. Final Classification and Labeling
    
    # --- THIS IS THE NEW FIX ---
    # If any high-priority rule was triggered, override the ML score
    if "Credential Theft" in rule_explanation or "Phishing Attempt" in rule_explanation:
        return "Scam Likely", f"{rule_explanation} (Critical rule override)"
    # --- END OF FIX ---

    if final_score > 0.7:
        classification = "Scam Likely"
        reason = f"{rule_explanation} (ML Score: {prob_score:.2f})"
    elif final_score > 0.4:
        classification = "Suspicious"
        reason = f"{rule_explanation} (ML Score: {prob_score:.2f})"
    elif prob_score > 0.5:
        classification = "Suspicious"
        reason = f"Label: Low Rule Score, but High ML Score ({prob_score:.2f})"
    else:
        classification = "Safe"
        reason = "Label: Not Scam (Passes all AI/Rule checks)"
        
    return classification, reason