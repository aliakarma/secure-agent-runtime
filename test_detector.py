from transformers import AutoTokenizer
from transformers import AutoModelForSequenceClassification
import torch

model_name = "protectai/deberta-v3-base-prompt-injection"

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(model_name)

print("Loading model...")
model = AutoModelForSequenceClassification.from_pretrained(model_name)

text = "Please read the uploaded image."

inputs = tokenizer(text, return_tensors="pt")

with torch.no_grad():
    outputs = model(**inputs)

scores = torch.softmax(outputs.logits, dim=1)

print(scores)