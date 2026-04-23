import json
from main import AnalyzeRequest, analyze_content
import asyncio

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

def run_tests():
    # Load models
    from main import load_models
    import main
    
    # Mock get_domain_age to avoid whois hangs
    def mock_get_domain_age(domain):
        if domain in ["github.com", "google.com"]:
            return None, 3650
        return None, 10
    main.get_domain_age = mock_get_domain_age

    load_models()

    errors = []
    results = []

    print("Running tests...\n")

    for tc in test_cases:
        request = AnalyzeRequest(url=tc["url"], text=tc["text"])
        
        try:
            response = analyze_content(request)
            actual_risk = response.risk
            explanation = response.explanation
            
            if actual_risk not in tc["expected"]:
                errors.append({
                    "Test ID": tc["id"],
                    "Test Name": tc["name"],
                    "Expected": " or ".join(tc["expected"]),
                    "Actual": actual_risk,
                    "Explanation": explanation
                })
            results.append({
                "Test ID": tc["id"],
                "Test Name": tc["name"],
                "Expected": " or ".join(tc["expected"]),
                "Actual": actual_risk,
                "Explanation": explanation,
                "Match": actual_risk in tc["expected"]
            })
        except Exception as e:
            errors.append({
                "Test ID": tc["id"],
                "Test Name": tc["name"],
                "Expected": " or ".join(tc["expected"]),
                "Actual": "INTERNAL ERROR",
                "Explanation": str(e)
            })

    # Output as markdown table
    print("| Test ID | Test Name | Expected | Actual | Match |")
    print("|---|---|---|---|---|")
    for r in results:
        print(f"| {r['Test ID']} | {r['Test Name']} | {r['Expected']} | {r['Actual']} | {'✅' if r['Match'] else '❌'} |")

    if errors:
        print("\nERRORS DETECTED:")
        print(json.dumps(errors, indent=4))
    else:
        print("\nAll tests passed successfully!")

if __name__ == "__main__":
    run_tests()
