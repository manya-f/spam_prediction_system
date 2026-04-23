import re
from urllib.parse import urlparse

def generate_explanation(text, url, text_score, url_score, domain_score, final_label):
    text_lower = text.lower()
    url_lower = url.lower()
    
    signals = []
    
    # 1. Detect urgency patterns
    urgency_patterns = ["urgent", "immediately", "emergency", "action required"]
    if any(word in text_lower for word in urgency_patterns):
        signals.append("uses urgency to pressure the user")
        
    # 2. Detect financial requests
    financial_patterns = ["send money", "bank details", "payment", "credit card"]
    if any(word in text_lower for word in financial_patterns):
        signals.append("requests sensitive financial data")
        
    # 3. Detect account-related terms
    account_patterns = ["verify", "login", "account", "password"]
    if any(word in text_lower for word in account_patterns):
        signals.append("asks for account verification, which is a common phishing tactic")
        
    # 4. Detect shortened URLs
    shorteners = ["bit.ly", "tinyurl", "t.co", "ow.ly", "is.gd", "goo.gl"]
    if any(shortener in url_lower for shortener in shorteners):
        signals.append("uses a shortened URL to hide the true destination")
        
    # 5. Detect suspicious domains
    parsed_url = urlparse(url_lower)
    domain = parsed_url.netloc or parsed_url.path
    if domain.startswith('www.'):
        domain = domain[4:]
        
    is_suspicious_domain = False
    if "xn--" in domain:
        is_suspicious_domain = True
    elif "-" in domain:
        is_suspicious_domain = True
    elif re.search(r'[0-9]', domain):
        is_suspicious_domain = True
        
    if is_suspicious_domain:
        signals.append("contains a suspicious domain structure (e.g., numbers, hyphens, or encoded characters)")
        
    # 6. If no strong signals
    if not signals:
        if final_label == "Safe":
            return "This content appears safe with no significant threats detected."
        elif final_label == "Suspicious":
            return "This content contains some unusual patterns and should be treated with caution."
        else:
            return "This content has been flagged as dangerous due to multiple risk signals."
            
    # Combine signals
    if len(signals) == 1:
        reasons = signals[0]
    elif len(signals) == 2:
        reasons = f"{signals[0]} and {signals[1]}"
    else:
        reasons = ", ".join(signals[:-1]) + f", and {signals[-1]}"
        
    return f"This content is {final_label.lower()} because it {reasons}."

if __name__ == "__main__":
    # Example outputs for Safe, Suspicious, Dangerous cases
    print("Safe:", generate_explanation("Hey, let's grab coffee", "http://google.com", 0.1, 0.1, 0.0, "Safe"))
    print("Suspicious:", generate_explanation("Unusual activity noticed", "http://go0gle.com", 0.5, 0.5, 0.5, "Suspicious"))
    print("Dangerous:", generate_explanation("Urgent! Verify your login", "http://paypal-update.com", 0.9, 0.8, 1.0, "Dangerous"))
