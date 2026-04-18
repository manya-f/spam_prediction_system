import difflib
from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def is_typosquat(domain):
    suspicious_map = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }

    for num, char in suspicious_map.items():
        if num in domain:
            possible = domain.replace(num, char)
            if any(brand in possible for brand in ["google","paypal","amazon","chatgpt"]):
                return True

    return False

def is_similar_to_brand(domain):
    brands = ["google", "paypal", "amazon", "microsoft", "apple", "chatgpt", "gemini", "instagram", "facebook", "whatsapp", "twitter", "linkedin", "netflix", "spotify", "hulu", "disney", "youtube", "tiktok", "threads"]
    
    domain_no_tld = domain.split('.')[0].lower()
    
    for brand in brands:
        if domain_no_tld == brand:
            continue
        similarity = difflib.SequenceMatcher(None, domain_no_tld, brand).ratio()
        if similarity > 0.7:
            return True

    return False

def calculate_trust_score(text_score, url_score, domain_age, url="", text=""):
    """
    Calculates an overall trust score based on weighted phishing probabilities.
    Includes high-risk rule overrides for hackathon demonstration.
    
    Args:
        text_score (float): Phishing probability from text model (0.0 to 1.0)
        url_score (float): Phishing probability from URL model (0.0 to 1.0)
        domain_age (int or None): Domain age in days.
        url (str): The raw URL for rule-based overrides.
        text (str): The raw text for rule-based overrides.
        
    Returns:
        tuple: (score (0-100), label (Safe / Suspicious / Dangerous))
    """
    url_lower = url.lower()
    text_lower = text.lower()
    
    domain = extract_domain(url)
    
    trusted_domains = ["google.com", "microsoft.com", "github.com", "wikipedia.org", "youtube.com"]
    if domain in trusted_domains:
        return 90, "Safe"

    if "xn--" in domain:
        return 25, "Dangerous"

    if is_typosquat(domain):
        return 20, "Dangerous"

    if is_similar_to_brand(domain):
        return 20, "Dangerous"
    
    # 🔥 RULE OVERRIDE (Hackathon Gold)
    # We use rule-based overrides for high-risk phishing patterns
    if "free-money" in url_lower or "win" in url_lower:
        return 10, "Dangerous"
        
    danger_phrases = [
        "send money",
        "bank details",
        "claim prize",
        "verify account",
        "urgent help",
        "emergency money"
    ]

    for phrase in danger_phrases:
        if phrase in text_lower:
            return 20, "Dangerous"

    if ("urgent" in text_lower or "emergency" in text_lower) and "money" in text_lower:
        return 15, "Dangerous"
        
    if "paypal" in url_lower and "verification" in url_lower:
        return 10, "Dangerous"
        
    if url_score > 0.6:
        return 25, "Dangerous"

    if not text.strip() and url_score > 0.5:
        return 20, "Dangerous"
        
    # Convert domain age into a risk score (0.0 = safe, 1.0 = risky)
    # If domain is < 6 months (180 days) or hidden, it's high risk
    domain_score = 1.0 if (domain_age is None or domain_age < 180) else 0.0
    
    safe_patterns = [
        "coffee",
        "notes",
        "meeting",
        "class",
        "assignment",
        "hangout",
        "grab coffee"
    ]

    if any(word in text_lower for word in safe_patterns):
        return 90, "Safe"

    if text_score < 0.15 and url_score == 0:
        return 90, "Safe"

    casual_patterns = ["hey", "can you", "when you get time"]

    if any(p in text_lower for p in casual_patterns):
        text_score *= 0.5
        
    # 🧠 Weighted NLP Risk Formula
    # URL risk and text risk are weighted equally, with a small penalty for new domains
    risk = (text_score * 0.3) + (url_score * 0.5) + (domain_score * 0.2)
    
    # Calculate Trust Score (Inversely proportional to risk, scale 0-100)
    trust_score = int((1.0 - risk) * 100)
    
    # Determine Label based on thresholds
    if trust_score > 80:
        label = "Safe"
    elif trust_score > 55:
        label = "Suspicious"
    else:
        label = "Dangerous"
        
    return trust_score, label

if __name__ == "__main__":
    # Quick tests to verify the logic
    test_cases = [
        {"text_score": 0.1, "url_score": 0.1, "age": 1000, "url": "https://google.com", "text": "Hello", "desc": "Low risk, old domain"},
        {"text_score": 0.4, "url_score": 0.4, "age": 30,   "url": "http://random-site.com", "text": "Hi", "desc": "Medium risk, new domain"},
        {"text_score": 0.8, "url_score": 0.2, "age": 1000, "url": "https://legit-site.com", "text": "Something", "desc": "Soft phishing (Text high, URL low)"},
        {"text_score": 0.2, "url_score": 0.8, "age": 100,  "url": "http://paypal-verification-secure.com", "text": "Hey", "desc": "Override Triggered!"},
        {"text_score": 0.1, "url_score": 0.1, "age": 1000, "url": "http://free-money.com", "text": "Claim now", "desc": "Free money override"},
        {"text_score": 0.1, "url_score": 0.1, "age": 1000, "url": "http://google.com", "text": "Bank verify", "desc": "Bank verify override"}
    ]
    
    print("Testing Weighted Trust Scorer Logic:\n")
    for case in test_cases:
        score, label = calculate_trust_score(case['text_score'], case['url_score'], case['age'], case['url'], case['text'])
        print(f"[{label:<10}] Score: {score:>3}/100 | URL: {case['url']} -> ({case['desc']})")
