# Malicious-Email-Scorer
A Gmail Add-on that analyzes an opened email and produces a  maliciousness score.
The Add-on is designed to be context-aware - once an email is opened, the user can immediately trigger the analysis by clicking "Scan for Threads"
_____________________________________________________________________________________________________________________________
### The Idea Behind the Feature
The logic behind these tests is based on the observation that attackers consistently follow specific patterns, such as using fake domains, 
deceptive usernames, malicious links or files, and social engineering to attack users. Under these circumstances, I decided to implement several tests to determine whether a received email can be considered malicious.

#### Scoring Method:
I developed a scoring method that calculates the risk level according to the potential threats existing within each specific email. The fact that the score is dynamic and calculated based only on relevant threats—rather than using a generic scoring method—provides a much better and more accurate indication of the true risk level.

#### Risk Assessment:
  The engine returns a structured response containing:
  * Risk Level: (LOW / MEDIUM / HIGH)
  *  Security Score: A percentage based on failed vs. passed tests.
  * Reasoning: A detailed list of specific threats detected.
    
_____________________________________________________________________________________________________________________________

### Key Features & Security Logic
* <ins>Infrastructure Validation:</ins> Real-time checking of SPF authentication and MX records to ensure the sender's domain exists and is authorized.
* <ins>Direct IP URL Detection:</ins> Identifies links that point directly to an IP address instead of a registered domain name. This is a high-confidence indicator of phishing, as legitimate organizations almost exclusively use domains.
* <ins>Brand Impersonation Detection:</ins> Cross-references the email content with official domains (PayPal, Google, Netflix…) to detect false domains and spoofing.
* <ins>Attachment Scanning:</ins> Detects dangerous file extensions (EXE, BAT, JS) and deceptive "Double Extensions" (e.g., invoice.pdf.exe) - usually used to trick the user.
* <ins>OSINT Reputation Check:</ins> Uses Google Search results to scan for scam reports related to entities mentioned in the email signature.
* <ins>Word Analysis:</ins> Scans for urgency/financial keywords and generic greetings ("Dear Customer") — which are characteristics of automated bulk phishing campaigns.
* <ins>URL Integrity Check:</ins> Detects empty, broken, or suspicious link structures (such as "#" or empty href attributes) that are often used in deceptive email layouts to hide malicious redirects.
_____________________________________________________________________________________________________________________________

### Security & Secrets:
* Handling Untrusted Input: The Add-on treats all incoming email data as untrusted. Only specific technical indicators (domains, links, and file headers) are extracted for analysis to minimize risk.
* Data Privacy: To protect user privacy, the backend analysis is designed to process technical security signals without storing or exposing the personal content of the email body.
_____________________________________________________________________________________________________________________________

## Setup & Installation
This repository contains all the components needed to run the analysis, split between the frontend (Google side) and the backend (Python side).

  ### 1. Backend (Python)
  Ensure you have Python 3.9+ installed.
  
  #### Clone the repository
    git clone [https://github.com/Adip19/Malicious-Email-Scorer.git](https://github.com/Adip19/Malicious-Email-Scorer.git)
    cd backend
  
    # Install dependencies
    pip install -r requirements.txt
  
    # Run the server
    uvicorn main:app --reload
  
  ### 2. Tunneling (ngrok)
  Ngrok is used to create a secure HTTPS tunnel. This allows the Gmail Add-on to communicate with the FastAPI server in real-time.
  To connect the two, the generated ngrok URL must be updated in the backendUrl variable within the Code.gs file.
  * Expose Local Port: Run ngrok http 8000 in your terminal. 
  * Copy URL: Copy the Forwarding URL generated (e.g., https://xxxx.ngrok-free.app). 
  * Persistence: Remember that the URL changes every time you restart ngrok.
  
  ### 3. Frontend (Google Apps Script)
  * The logic for the Gmail interface is contained in the Google Apps Script files:
  * Code.gs: This file handles the extraction of the email data (Subject, Sender, Body, Attachments) and communicates with the backend security engine.
  * appsscript.json: The manifest file that defines the permissions required for the Add-on to read email metadata and perform URL fetches.

_____________________________________________________________________________________________________________________________

## Future Improvements:
* <ins>Language Support:</ins> Currently, the feature is built to analyze emails in English. If a malicious email arrives in a different language, there is a risk of incorrect detection.
* <ins>Reputation Analysis:</ins> The reputation check is currently limited to a selected number of sources from Google search. In the future, I would like to include a deeper analysis of more online sources and social media, potentially using NLP models.
* <ins>Domain Testing:</ins> The domain test is currently limited to well-known companies (Google, Microsoft, etc.). Also, not every "cousin domain" is identified if the brand name isn't explicitly in the sender's email.
* <ins>Authentication (SPF):</ins> SPF testing has limitations (when an email is sent to yourself (Self-sent), it might automatically be marked as reliable). I added logic to mark this as a potential risk, but a deeper analysis should be done.
* <ins>UI/UX Enhancements:</ins> Improving the Add-on's visual design to be more intuitive and engaging.



