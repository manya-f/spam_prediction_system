import streamlit as st
import os
from phishing_classifier import PhishingClassifierInference, train_phishing_model

st.set_page_config(page_title="Phishing Email Detector", page_icon="🎣", layout="centered")

st.title("🎣 Phishing Email Detector MVP")
st.markdown("This hackathon MVP uses a fine-tuned DistilBERT model to predict whether an email is phishing or safe.")

# Initialize or load model
@st.cache_resource
def load_model():
    if os.path.exists("./phishing_model"):
        return PhishingClassifierInference("./phishing_model")
    return None

model = load_model()

if model is None:
    st.warning("Model not found! You need to train the model first.")
    if st.button("Train Model Now (Takes a few minutes)"):
        with st.spinner("Training model... Please wait."):
            # We train for 1 epoch to be super lightweight
            train_phishing_model(epochs=1)
            st.success("Training complete! Reloading...")
            st.rerun()
else:
    st.success("Model loaded and ready for inference!")
    
    # UI for text input
    st.subheader("Analyze an Email")
    email_text = st.text_area("Paste the email content below:", height=150, 
                              placeholder="Dear user, your account will be locked...")
    
    if st.button("Check for Phishing"):
        if not email_text.strip():
            st.error("Please enter some text to analyze.")
        else:
            with st.spinner("Analyzing..."):
                result = model.predict(email_text)
                
                prob = result["phishing_probability"]
                is_phishing = result["is_phishing"]
                
                st.markdown("### Results:")
                
                if is_phishing:
                    st.error(f"🚨 **PHISHING DETECTED** (Probability: {prob:.2%})")
                    st.progress(prob)
                    st.markdown("This email exhibits characteristics common in phishing attempts. Proceed with extreme caution.")
                else:
                    st.success(f"✅ **SAFE EMAIL** (Phishing Probability: {prob:.2%})")
                    st.progress(prob)
                    st.markdown("This email appears to be legitimate.")

st.markdown("---")
st.caption("Powered by HuggingFace Transformers & Streamlit")
