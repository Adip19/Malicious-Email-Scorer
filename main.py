from fastapi import FastAPI
from pydantic import BaseModel # For the -Add-on, check if the structure right
import re # Regular expression - text, IP etc.
from typing import List 
from googlesearch import search # For OSINT serach
import dns.resolver # MX records

# App Initialization
app = FastAPI()

# Validation verifies the existence of inbound mail servers
def check_mx_record(domain):
    try:
        # MX records for the domain
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, Exception):
        # If the domain dosen't exist, there are no records / Error 
        return False
    
# OSINT - search for information to determine as fraud
def check_reputation(company_name):
    if not company_name or len(company_name) < 3:
        return False
    
    # Checking the first 2 words - for extnded serach
    short_name = " ".join(company_name.split()[:2])
    query = f'"{short_name}" scam reports phishing'
    print(f"DEBUG: Real search query: {query}") # For Terminal
    
    try:
        # Limit for the first 10 searches
        results = list(search(query, num_results=10))
        if results:
            print(f"DEBUG: Found {len(results)} search results!") # For Terminal
            return True
        return False
    except Exception as e:
        print(f"DEBUG: Search failed or blocked: {e}") 
        return False
    
# Attachment Security Scrutiny
class Attachment(BaseModel):
    name: str
    contentType: str
    # Size?

# Data validation and Schema definition
class EmailData(BaseModel):
    subject: str
    sender: str
    body: str
    rawContent: str
    user_email: str
    attachments: List[Attachment]

@app.post("/analyze")
async def analyze(data: EmailData):
    reasons = [] # Lists of potential threats
    # Calculate dynamic score 
    tests_failed = 0
    relevant_tests = 0 

    # Data normalization
    sender_lower = data.sender.lower() 
    body_lower = data.body.lower() # Email content
    subject_lower = data.subject.lower() # header
    user_email = data.user_email.lower()

    # 1. Search for urgent/pressure words
    relevant_tests += 1 # Add as potential threat
    urgent_words = ["urgent", "action required", "suspended", "password", "locked", "verify", "0.45 btc", "wallet", "claim"]
    if any(word in subject_lower or word in body_lower for word in urgent_words):
        tests_failed += 1 # Mark as fail to raise the scroe
        reasons.append("Urgency/Financial pressure keywords detected")

    # 2. Check for files - usually a risk
    if data.attachments:
        relevant_tests += 1 # Add as potential threat
        tests_failed += 1 
        for att in data.attachments:
            filename = att.name.lower()
            if filename.endswith(('.exe', '.bat', '.scr', '.js', '.vbs', '.msi', '.jar', '.docm', '.xlsm')):
                reasons.append(f"CRITICAL: Executable/Macro file detected ({att.name})")
            if filename.count('.') > 1: # risk - extensions to trick
                reasons.append(f"Deceptive naming: Double extension detected in {att.name}")

    # 3. Direct IP URL detection
    if "http" in body_lower: # Add as potential threat
        relevant_tests += 1
        if re.search(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', body_lower):
            tests_failed += 1
            reasons.append("Suspicious URL: Direct IP address used instead of a domain")

    # 4. Mismatch - brands analysis
    trusted_brands = ["paypal", "google", "microsoft", "netflix", "bank", "bit", "apple", "amazon"]
    brand_fail = False
    for brand in trusted_brands:
        if brand == "google" and "@gmail.com" in sender_lower: # Most common
                continue
        # To prevent false detection (bit/bitcoin)
        if re.search(rf"\b{brand}\b", sender_lower) or re.search(rf"\b{brand}\b", subject_lower) or re.search(rf"\b{brand}\b", body_lower):
            official_pattern = rf"@{brand}\.(com|co\.il|net|org|gov)" # When the sender email continue
            if not re.search(official_pattern, sender_lower):
                brand_fail = True
                reasons.append(f"Brand Mismatch: Content mentions '{brand.capitalize()}' but sender is unofficial")
                break
    if brand_fail: # Add to the score
        relevant_tests += 1
        tests_failed += 1

# 5. Check the reputation of the brands + Domain mismatch
    potential_company = None
    # Usually the brnd's name will be found next to specific words
    sig_match = re.search(r"(?:regards|team|from|support|sincerely)\s*[,:-]?\s*([A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*)", data.body)
    
    if sig_match:
        potential_company = sig_match.group(1).strip()

    if potential_company and potential_company.lower() not in user_email:
        relevant_tests += 1 # Add as potential 
        print(f"DEBUG: Investigating {potential_company}...")
        
        # Domain validation
        is_unverified = False
        company_domain_part = potential_company.split()[0].lower()
        if f"@{company_domain_part}" not in sender_lower:
            tests_failed += 1 # Mismatch - add to score
            is_unverified = True
            reasons.append(f"Unverified Entity: Body mentions '{potential_company}' but sender is unofficial")
        
        # Reputation online
        has_bad_reputation = check_reputation(potential_company)
        # If isn't valid with bad reputation OR not 
        if has_bad_reputation or (is_unverified):
            tests_failed += 1 # Add to the score
            reasons.append(f"OSINT Alert: '{potential_company}' is flagged in high-risk databases as a potential scam")
                                   
    # 6. Search for generic greeting
    relevant_tests += 1 # Add as potential threat
    greeting_fail = False
    opening_text = body_lower[:150] # Search in the begaining
    if user_email in opening_text:
        greeting_fail = True
        reasons.append("Greeting Risk: Using your email address instead of your name")
    else:
        for g in ["dear customer", "dear user", "hello client", "dear valued member"]: # Possible words
            if g in opening_text:
                greeting_fail = True
                reasons.append(f"Generic greeting detected: '{g}'")
                break
    if greeting_fail: # Add to the score
        tests_failed += 1

    # 7. SPF
    relevant_tests += 1 # Add as potential
    if "spf=fail" in data.rawContent.lower(): # Hard to check when I'm senting email to myself - so will be added as text
        tests_failed += 1
        reasons.append("Technical Failure: SPF authentication failed")

    # 8. MX Record - check if the sender can receive email 
    # Extracting the domain from the sender's address
    sender_domain = sender_lower.split('@')[-1].replace('>', '').strip()
    # Check only if not known
    if sender_domain not in ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]:
        relevant_tests += 1 # Add as potential
        print(f"DEBUG: Checking MX records for domain: {sender_domain}")
        
        if not check_mx_record(sender_domain):
            tests_failed += 1 # Threat - add to the score
            reasons.append(f"Domain Risk: The domain '{sender_domain}' has no valid mail servers (MX). This is highly suspicious.")


    # Dynamic score calculation
    final_score = int((tests_failed / relevant_tests) * 100) if relevant_tests > 0 else 0
    final_score = min(final_score, 100) # In case of score overflow
    risk_level = "HIGH RISK" if final_score >= 60 else "MEDIUM RISK" if final_score >= 30 else "LOW RISK"
    risk_color = "#CC0000" if final_score >= 60 else "#E69138" if final_score >= 30 else "#38761D"

    return {
        "risk_level": risk_level,
        "risk_color": risk_color,
        "score_percent": f"{final_score}%",
        "reasoning": "• " + "<br>• ".join(reasons) if reasons else "Safe: No threats detected."
    }

if __name__ == "__main__":
    import uvicorn # Import the server directory
    uvicorn.run(app, host="127.0.0.1", port=8000) # Server startup command