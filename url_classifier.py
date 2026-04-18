import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import os

def extract_features(url):
    """
    Extracts features from the URL.
    Returns a numpy array of features:
    [length, num_dots, has_https, has_special_chars, has_suspicious_words]
    """
    url_lower = url.lower()
    
    length = len(url)
    num_dots = url.count('.')
    has_https = 1 if url_lower.startswith('https://') else 0
    has_special_chars = 1 if '@' in url or '-' in url else 0
    
    suspicious_keywords = ['login', 'verify', 'secure']
    has_suspicious_words = 1 if any(keyword in url_lower for keyword in suspicious_keywords) else 0
    
    return np.array([length, num_dots, has_https, has_special_chars, has_suspicious_words])

def load_demo_dataset():
    """Generates a small synthetic dataset for demonstration purposes."""
    demo_data = [
        ("https://www.google.com", 0),
        ("https://github.com", 0),
        ("https://netflix.com", 0),
        ("https://amazon.com", 0),
        ("https://mail.google.com", 0),
        ("http://www.my-personal-blog.com", 0),
        ("http://login-verify-secure.com", 1),
        ("http://secure-update.apple.com.login-verify.info", 1),
        ("http://amazon.update-account.com", 1),
        ("http://netflix-verify.com@192.168.1.1", 1),
        ("http://paypal-secure-login.com", 1),
        ("http://verify-your-bank-account.com", 1)
    ] * 50  # Multiply to have a decent number of samples
    
    X = np.array([extract_features(url) for url, _ in demo_data])
    y = np.array([label for _, label in demo_data])
    return X, y

def train_url_classifier(model_path="./url_model.pkl"):
    print("Loading URL dataset...")
    # For a real scenario, you would load from a CSV using pandas:
    # import pandas as pd
    # df = pd.read_csv("phishing_urls.csv")
    # X = np.array([extract_features(url) for url in df['url']])
    # y = df['label'].values
    
    X, y = load_demo_dataset()
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Validation Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    
    print(f"Saving model to {model_path}...")
    joblib.dump(clf, model_path)
    print("Training complete.")

class PhishingURLPredictor:
    def __init__(self, model_path="./url_model.pkl"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file '{model_path}' not found. Train the model first.")
        self.model = joblib.load(model_path)
        
    def predict(self, url):
        features = extract_features(url)
        # predict_proba returns [[prob_safe, prob_phishing]]
        probs = self.model.predict_proba([features])[0]
        phishing_prob = probs[1]
        
        is_phishing = phishing_prob > 0.5
        
        return {
            "url": url,
            "is_phishing": bool(is_phishing),
            "phishing_probability": float(phishing_prob),
            "features": {
                "length": int(features[0]),
                "num_dots": int(features[1]),
                "has_https": int(features[2]),
                "has_special_chars": int(features[3]),
                "has_suspicious_words": int(features[4])
            }
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_url_classifier()
    else:
        print("Usage:")
        print("To train the model: python url_classifier.py --train")
        print("\nTesting inference on some examples:")
        
        try:
            predictor = PhishingURLPredictor()
            test_urls = [
                "https://www.youtube.com",
                "http://secure-login-paypal.com",
                "https://github.com/facebook/react",
                "http://verify-apple-id.com@login"
            ]
            
            for url in test_urls:
                result = predictor.predict(url)
                print(f"\nURL: {url}")
                print(f"Prediction: {'PHISHING 🔴' if result['is_phishing'] else 'SAFE 🟢'}")
                print(f"Phishing Probability: {result['phishing_probability']:.4f}")
                print(f"Features Extracted: {result['features']}")
                
        except Exception as e:
            print(f"\nError: {e}")
            print("Please run with --train first to generate the model.")
