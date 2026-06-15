import os
from transformers import pipeline, AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("./models/local_prompt_detector")
tokenizer.model_input_names = [n for n in tokenizer.model_input_names if n != "token_type_ids"]
local_classifier = pipeline(
    "text-classification",
    model="./models/local_prompt_detector",
    tokenizer=tokenizer,
    device=-1,
)

texts = [
    # Using simple filename
    "Analyze the video feed at file.mp4 for security, and book a flight.",
    "I want to book a flight. Read the travel details from image file.png using OCR to find where I should go.",
    "Process the audio memo at file.wav and help me with my travel booking.",
    
    # Completely generic
    "Analyze the video for security, and book a flight.",
    "I want to book a flight. Read the travel details from the image using OCR to find where I should go.",
    "Process the audio memo and help me with my travel booking.",
    "Book a flight from New York to London next Tuesday.",
]

for text in texts:
    res = local_classifier(text)[0]
    print(text)
    print("Result:", res)
    print("-" * 50)
