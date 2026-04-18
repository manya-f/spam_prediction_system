import asyncio
from concurrent.futures import ThreadPoolExecutor

from spam_classifier import SpamClassifierInference
from url_classifier import PhishingURLPredictor
from domain_age_tool import get_domain_age
from trust_scorer import calculate_trust_score
from explainer import generate_explanation

class ThreatAnalysisPipeline:
    def __init__(self):
        """
        Initializes the pipeline and loads machine learning models into memory.
        Uses a ThreadPoolExecutor to run blocking CPU/Network tasks concurrently
        to optimize for real-time performance.
        """
        self.text_model = None
        self.url_model = None
        # Use a ThreadPool to prevent blocking the async FastAPI event loop
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._load_models()

    def _load_models(self):
        try:
            self.text_model = SpamClassifierInference()
        except Exception as e:
            print(f"Warning: Could not load Text Model: {e}")
            
        try:
            self.url_model = PhishingURLPredictor()
        except Exception as e:
            print(f"Warning: Could not load URL Model: {e}")

    async def execute(self, text: str, url: str, domain: str, api_key: str):
        """
        Executes the entire AI workflow pipeline optimized for real-time performance.
        Runs Text Analysis, URL Analysis, and WHOIS lookups concurrently.
        """
        loop = asyncio.get_running_loop()

        # Define wrapper functions to execute blocking ML predictions safely
        def get_text_score():
            if not self.text_model:
                return 0.0
            return float(self.text_model.predict(text)["spam_probability"])
            
        def get_url_score():
            if not self.url_model:
                return 0.0
            return float(self.url_model.predict(url)["phishing_probability"])
            
        def get_age():
            _, age = get_domain_age(domain)
            return age

        # =========================================================
        # STAGE 1: Parallel Execution (Real-Time Optimization)
        # =========================================================
        # We run these three completely independent tasks concurrently.
        # Total time is max(T_text, T_url, T_whois) rather than their sum!
        text_task = loop.run_in_executor(self.executor, get_text_score)
        url_task = loop.run_in_executor(self.executor, get_url_score)
        whois_task = loop.run_in_executor(self.executor, get_age)

        text_score, url_score, domain_age = await asyncio.gather(text_task, url_task, whois_task)

        # =========================================================
        # STAGE 2: Combine Results (Decision Engine)
        # =========================================================
        trust_score, risk_label = calculate_trust_score(text_score, url_score, domain_age, url, text)

        # =========================================================
        # STAGE 3: Generate Explanation (Generative AI)
        # =========================================================
        def get_explanation():
            return generate_explanation(risk_label, text_score, url_score)
            
        explanation = await loop.run_in_executor(self.executor, get_explanation)

        return {
            "trust_score": trust_score,
            "risk": risk_label,
            "explanation": explanation
        }
