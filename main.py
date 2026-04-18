from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import os
import difflib
from dotenv import load_dotenv

# Load environment variables from .env file securely
load_dotenv()

from spam_classifier import SpamClassifierInference
from domain_age_tool import get_domain_age
from trust_scorer import calculate_trust_score, extract_domain, is_similar_to_brand
from explainer import generate_explanation

app = FastAPI(
    title="PhishGuard API",
    description="Backend API for analyzing URLs and emails/text for phishing risks.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str
    text: str

class AnalyzeResponse(BaseModel):
    trust_score: int
    risk: str
    explanation: str

classifier = None

@app.on_event("startup")
def load_models():
    global classifier
    try:
        classifier = SpamClassifierInference("./spam_classifier_model")
        print("✅ Text Model loaded successfully.")
    except Exception as e:
        print(f"⚠️ Warning: Could not load Text Model: {e}")
        print("Please ensure you have run 'python spam_classifier.py --train' first.")


def scam_text_boost(text):
    text = text.lower()

    high_risk = [
        "bank details",
        "send money",
        "claim prize",
        "winner",
        "lottery",
        "crypto",
        "airdrop",
        "token"
    ]

    medium_risk = [
        "verify",
        "login",
        "account",
        "urgent"
    ]

    score = 0

    for word in high_risk:
        if word in text:
            score += 0.4   # strong boost

    for word in medium_risk:
        if word in text:
            score += 0.1

    return min(score, 1)

def predict_url_risk(url: str) -> float:
    """Rule-based URL risk detection (Hackathon quick fix)"""
    score = 0
    url_lower = url.lower()
    
    if "@" in url:
        score += 30
    if len(url) > 75:
        score += 20
    if "https" not in url_lower:
        score += 20
        
    # Penalize weird domain structures common in phishing
    if "-" in url:
        score += 10
        
    domain = extract_domain(url)
    if is_similar_to_brand(domain):
        score += 50
        
    if any(char.isdigit() for char in domain):
        score += 20

    if any(brand in domain for brand in ["google", "paypal", "amazon"]):
        score += 20
    suspicious_terms = [
        "secure", "login", "verify",
        "update", "account", "free", "money"
    ]

    for term in suspicious_terms:
        if term in url_lower:
            score += 10
            
    # Brand impersonation detection
    suspicious_brands = ["paypal", "amazon", "bank", "google", "login", "verify"]
    for word in suspicious_brands:
        if word in url_lower:
            score += 10
            
    return min(1.0, score / 100.0)

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_content(request: AnalyzeRequest):
    # 1. Text Model Prediction
    text_score = 0.0
    if classifier:
        try:
            text_result = classifier.predict(request.text)
            text_score = float(text_result["spam_probability"])
            text_score = min(text_score, 0.4)
        except Exception as e:
            print(f"Text prediction error: {e}")
            
    text_score += scam_text_boost(request.text)
    text_score = min(text_score, 1.0)
            
    # 2. Rule-based URL risk (replaces ML model)
    url_score = predict_url_risk(request.url)
    
    # 3. Domain Age
    domain = extract_domain(request.url)
    _, domain_age = get_domain_age(domain)
    
    # 4. Trust Score (includes hardcoded rule overrides)
    trust_score, risk_label = calculate_trust_score(text_score, url_score, domain_age, request.url, request.text)
    
    # 5. Explainer
    explanation = generate_explanation(risk_label, text_score, url_score)
    
    return AnalyzeResponse(
        trust_score=trust_score,
        risk=risk_label,
        explanation=explanation
    )

if __name__ == "__main__":
    import uvicorn
    # Ignore deprecation warning about on_event for MVP purposes
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
