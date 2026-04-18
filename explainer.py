def generate_explanation(label, text_score=0, url_score=0, *args, **kwargs):
    if label == "Dangerous":
        return "This content shows strong indicators of a phishing or scam attempt. It is unsafe to interact with."
    elif label == "Suspicious":
        return "This content contains some warning signs. It is recommended to proceed with caution."
    else:
        return "This content appears safe with no major phishing indicators detected."

if __name__ == "__main__":
    print(generate_explanation("Dangerous"))
    print(generate_explanation("Suspicious"))
    print(generate_explanation("Safe"))
