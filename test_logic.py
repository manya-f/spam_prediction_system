from trust_scorer import calculate_trust_score, extract_domain
from explainer import generate_explanation
import json

test_cases = [
    {
        "id": "1",
        "name": "Fake Internship Scam",
        "url": "https://careers-google-apply-now.xyz",
        "text": "Congratulations! You have been selected for a Google internship. Please submit your documents and bank details to proceed.",
        "expected": ["Dangerous"]
    },
    {
        "id": "2",
        "name": "Legit Domain + Phishing Message",
        "url": "https://github.com",
        "text": "Security alert: Your account will be suspended. Please verify your credentials immediately.",
        "expected": ["Suspicious", "Dangerous"]
    },
    {
        "id": "3",
        "name": "Shortened URL Trap",
        "url": "http://bit.ly/verify-account-now",
        "text": "Click this link to confirm your account immediately to avoid suspension.",
        "expected": ["Dangerous"]
    },
    {
        "id": "4",
        "name": "Normal Message (Control Test)",
        "url": "-",
        "text": "Hey, are we still meeting for the project discussion at 5 PM?",
        "expected": ["Safe"]
    },
    {
        "id": "5",
        "name": "Advanced Typosquatting",
        "url": "https://paypa1-secure-login.com",
        "text": "PayPal Notice: Suspicious activity detected. Log in now to secure your account.",
        "expected": ["Dangerous"]
    }
]

# Simple mocks for what main.py does
def get_text_score(text):
    text = text.lower()
    score = 0.0 # Pretend model gave 0.0
    high_risk = ["bank details", "send money", "claim prize", "winner", "lottery", "crypto", "airdrop", "token"]
    medium_risk = ["verify", "login", "account", "urgent"]
    for word in high_risk:
        if word in text:
            score += 0.4
    for word in medium_risk:
        if word in text:
            score += 0.1
    return min(score, 1.0)

def predict_url_risk(url):
    score = 0
    url_lower = url.lower()
    if "@" in url: score += 30
    if len(url) > 75: score += 20
    if "https" not in url_lower: score += 20
    if "-" in url: score += 10
    domain = extract_domain(url)
    if any(char.isdigit() for char in domain): score += 20
    if any(brand in domain for brand in ["google", "paypal", "amazon"]): score += 20
    suspicious_terms = ["secure", "login", "verify", "update", "account", "free", "money"]
    for term in suspicious_terms:
        if term in url_lower: score += 10
    return min(1.0, score / 100.0)

def mock_get_domain_age(domain):
    if domain in ["github.com", "google.com"]: return 3650
    return 10

print("| Test ID | Test Name | Expected | Actual | Match | Explanation |")
print("|---|---|---|---|---|---|")

for tc in test_cases:
    url = tc["url"]
    text = tc["text"]
    
    # 1. Text Score
    text_score = get_text_score(text)
    
    # 2. URL Score
    url_score = predict_url_risk(url)
    
    # 3. Domain Age
    domain = extract_domain(url)
    domain_age = mock_get_domain_age(domain)
    domain_score = 1.0 if (domain_age is None or domain_age < 180) else 0.0
    
    # 4. Trust Score
    trust_score, risk_label = calculate_trust_score(text_score, url_score, domain_age, url, text)
    
    # 5. Explainer
    explanation = generate_explanation(text, url, text_score, url_score, domain_score, risk_label)
    
    match = risk_label in tc["expected"]
    match_str = "PASS" if match else "FAIL"
    
    print(f"| {tc['id']} | {tc['name']} | {' or '.join(tc['expected'])} | {risk_label} | {match_str} | {explanation} |")
