import torch
from datasets import load_dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import os

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary', zero_division=0)
    acc = accuracy_score(labels, preds)
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

def train_phishing_model(output_dir="./phishing_model", epochs=2):
    print("Loading Email dataset (Enron Spam/Phishing)...")
    # Using a small, standard email spam/phishing dataset for demonstration
    # SetFit/enron_spam has 'text' and 'label' (0=ham, 1=spam/phishing)
    try:
        dataset = load_dataset("SetFit/enron_spam")
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        print("Fallback: Using 'sms_spam' instead.")
        dataset = load_dataset("sms_spam")
        # Rename 'sms' to 'text' for consistency if using fallback
        if 'sms' in dataset['train'].column_names:
            dataset = dataset.rename_column('sms', 'text')

    # We use a small subset for demonstration to keep it lightweight (Hackathon MVP)
    # Using 500 samples for training and 100 for evaluation
    small_train_dataset = dataset["train"].shuffle(seed=42).select(range(500))
    small_eval_dataset = dataset["test"].shuffle(seed=42).select(range(100))
    
    print("Loading tokenizer...")
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    
    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)
    
    print("Tokenizing dataset...")
    tokenized_train = small_train_dataset.map(tokenize_function, batched=True)
    tokenized_eval = small_eval_dataset.map(tokenize_function, batched=True)
    
    print("Loading model...")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2
    )
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        eval_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        num_train_epochs=epochs,
        weight_decay=0.01,
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_eval,
        compute_metrics=compute_metrics,
    )
    
    print("Starting training...")
    trainer.train()
    
    print("Saving final model...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"Model saved to {output_dir}")

class PhishingClassifierInference:
    def __init__(self, model_dir="./phishing_model"):
        if not os.path.exists(model_dir):
            raise FileNotFoundError(f"Model directory '{model_dir}' not found. Please train the model first.")
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_dir)
        self.model.eval()
        
    def predict(self, text):
        inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=128)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        
        phishing_prob = probs[0][1].item()
        
        is_phishing = phishing_prob > 0.5
        return {
            "is_phishing": is_phishing,
            "phishing_probability": phishing_prob,
            "text": text
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_phishing_model()
    else:
        print("Usage:")
        print("To train the model: python phishing_classifier.py --train")
        print("\nTesting inference on some examples (requires a trained model):")
        try:
            classifier = PhishingClassifierInference()
            
            test_messages = [
                "Hi John, please review the attached quarterly report by Friday.",
                "URGENT: Your account has been suspended. Please click here to verify your login credentials immediately.",
                "Hey, are we still on for the meeting tomorrow?",
                "You have been selected for a $1000 Walmart Gift Card! Submit your banking details to claim your reward."
            ]
            
            for msg in test_messages:
                result = classifier.predict(msg)
                print(f"[{'PHISHING' if result['is_phishing'] else 'SAFE    '}] (Prob: {result['phishing_probability']:.4f}) - {msg}")
                
        except Exception as e:
            print(f"\nError: {e}")
            print("Please run with --train first to train the model.")
