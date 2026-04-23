import requests
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

url_endpoint = "http://localhost:8000/analyze"
errors = []

print("Running tests...\n")

for tc in test_cases:
    payload = {
        "url": tc["url"],
        "text": tc["text"]
    }
    try:
        response = requests.post(url_endpoint, json=payload)
        response.raise_for_status()
        result = response.json()
        
        actual_risk = result.get("risk")
        explanation = result.get("explanation", "No explanation")
        
        if actual_risk not in tc["expected"]:
            errors.append({
                "Test ID": tc["id"],
                "Test Name": tc["name"],
                "Expected": " or ".join(tc["expected"]),
                "Actual": actual_risk,
                "Explanation": explanation
            })
    except Exception as e:
        errors.append({
            "Test ID": tc["id"],
            "Test Name": tc["name"],
            "Expected": " or ".join(tc["expected"]),
            "Actual": "API ERROR",
            "Explanation": str(e)
        })

if not errors:
    print("All tests passed successfully! No errors found.")
else:
    print("ERRORS FOUND:\n")
    print(json.dumps(errors, indent=4))
