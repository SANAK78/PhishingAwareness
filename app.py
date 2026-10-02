import os
import re
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = 'phishing_defense_simulation_key_2026'

# ====== 1. SECURE AUDIT LOGGING (Zero Plaintext Credential Leak) ======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'phishing_audit.log')

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

@app.route('/')
def mock_login():
    """Simulated Deceptive Login Page"""
    return render_template('index.html')

@app.route('/login-attempt', methods=['POST'])
def capture_attempt():
    """
    Simulated credential interceptor.
    Cybersecurity Rule: Never store passwords entered in phishing tests!
    """
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')

    # Input Validation
    if not email or not re.match(EMAIL_REGEX, email):
        logging.warning(f"PHISHING_SIMULATION: Invalid/Malformed Email Attempt | Client_IP: {request.remote_addr}")
        return redirect(url_for('awareness', status='invalid'))

    # Security Logging - Audit Event
    client_ip = request.remote_addr or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Audit log (Only recording that user was caught, safe telemetry)
    logging.info(
        f"SIMULATION_CAUGHT: User fell for mock phishing | "
        f"Target_Email: {email} | IP: {client_ip} | "
        f"Password_Length: {len(password)} chars (Zero-Stored) | "
        f"Device: {user_agent[:45]}"
    )

    # Immediately redirect to the educational awareness hub
    return redirect(url_for('awareness', email=email))

@app.route('/awareness')
def awareness():
    email = request.args.get('email', 'operator@securecorp.internal')
    return render_template('awareness.html', target_email=email)

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    """Security Check Utility: Analyzes deceptive URLs for Phishing Red Flags"""
    data = request.get_json() or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'safe': False, 'flags': ['URL cannot be empty']})

    flags = []
    # Check 1: IP address as hostname
    if re.search(r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', url):
        flags.append("Contains raw IP address instead of domain name.")

    # Check 2: Suspicious deceptive keywords
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'update', 'password']
    matched_words = [w for w in suspicious_keywords if w in url.lower() and not url.lower().startswith(f"https://{w}")]
    if len(matched_words) >= 2:
        flags.append(f"Multiple deceptive authentication keywords detected ({', '.join(matched_words)}).")

    # Check 3: Excessive subdomains or hyphens
    if url.count('-') >= 3:
        flags.append("High number of hyphens simulating corporate brand name.")
    if url.count('.') >= 4:
        flags.append("Suspicious deeply nested subdomains detected.")

    # Check 4: Insecure protocol
    if url.startswith('http://'):
        flags.append("Unencrypted connection (HTTP).")

    is_suspicious = len(flags) > 0
    return jsonify({
        'safe': not is_suspicious,
        'flags': flags if flags else ["Domain passed heuristic security filters."]
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)