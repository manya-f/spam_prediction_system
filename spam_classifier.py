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

def train_spam_classifier(output_dir="./spam_classifier_model", epochs=3):
    print("Loading SMS Spam dataset...")
    # sms_spam dataset: 'label' (0=ham, 1=spam) and 'sms' (text)
    try:
        dataset = load_dataset("sms_spam")
    except Exception as e:
        print(f"Failed to load sms_spam dataset: {e}")
        print("Fallback: Using 'uciml/sms_spam' instead.")
        dataset = load_dataset("uciml/sms_spam")

    # Note: 'sms_spam' has 'train' split. It has 'sms' and 'label' columns.
    dataset = dataset["train"].train_test_split(test_size=0.2, seed=42)
    
    print("Loading tokenizer...")
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    
    def tokenize_function(examples):
        return tokenizer(examples["sms"], padding="max_length", truncation=True, max_length=128)
    
    print("Tokenizing dataset...")
    tokenized_datasets = dataset.map(tokenize_function, batched=True)
    
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
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        compute_metrics=compute_metrics,
    )
    
    print("Starting training...")
    trainer.train()
    
    print("Saving final model...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"Model saved to {output_dir}")

class SpamClassifierInference:
    def __init__(self, model_dir="./spam_classifier_model"):
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_dir)
        self.model.eval()
        
    def predict(self, text):
        inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=128)
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            
        # Get probabilities using softmax
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        
        # Class 1 is Spam, Class 0 is Ham
        spam_prob = probs[0][1].item()
        
        is_spam = spam_prob > 0.5
        return {
            "is_spam": is_spam,
            "spam_probability": spam_prob,
            "text": text
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_spam_classifier()
    else:
        print("Usage:")
        print("To train the model: python spam_classifier.py --train")
        print("\nTesting inference on some examples (requires a trained model):")
        try:
            classifier = SpamClassifierInference()
            
            test_messages = [
                "Hey, are we still meeting for lunch today?",
                "URGENT! You have won a 1 week FREE membership in our $100,000 Prize Jackpot! Txt the word: CLAIM to No: 81010",
                "Can you review my PR by tonight?",
                "Congratulations! Your credit score entitles you to a no-interest Visa credit card. Click here to claim."
            ]
            
            for msg in test_messages:
                result = classifier.predict(msg)
                print(f"[{'SPAM' if result['is_spam'] else 'HAM '}] (Prob: {result['spam_probability']:.4f}) - {msg}")
                
        except Exception as e:
            print(f"\nCould not load model for inference: {e}")
            print("Please run with --train first to train the model.")
