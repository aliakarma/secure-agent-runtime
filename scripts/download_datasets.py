import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from logging_config import get_logger

logger = get_logger(__name__)

def download_data():
    try:
        from datasets import load_dataset
        logger.info("Downloading deepset/prompt-injections dataset from Hugging Face...")
        
        # Load the dataset
        dataset = load_dataset("deepset/prompt-injections")
        
        # Convert splits to pandas DataFrames
        train_df = pd.DataFrame(dataset["train"])
        
        # The dataset might not have a formal validation/test split, so we split it manually
        logger.info(f"Loaded {len(train_df)} total raw samples.")
        
        # Shuffle dataset
        train_df = train_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Split: 80% train, 20% test
        split_idx = int(0.8 * len(train_df))
        train_split = train_df.iloc[:split_idx]
        test_split = train_df.iloc[split_idx:]
        
        # Ensure output directory exists
        os.makedirs("datasets", exist_ok=True)
        
        # Save to CSV
        train_path = "datasets/classifier_train.csv"
        test_path = "datasets/classifier_test.csv"
        
        train_split.to_csv(train_path, index=False)
        test_split.to_csv(test_path, index=False)
        
        logger.info(f"Successfully saved training set to {train_path} ({len(train_split)} samples)")
        logger.info(f"Successfully saved testing set to {test_path} ({len(test_split)} samples)")
        print("\nDataset download and preparation complete!")
        print(f"Train split: {train_path} ({len(train_split)} rows)")
        print(f"Test split: {test_path} ({len(test_split)} rows)")
        
    except ImportError:
        logger.error("Hugging Face datasets library is not installed. Please run pip install datasets first.")
    except Exception as e:
        logger.error(f"Failed to download dataset: {e}")

if __name__ == "__main__":
    download_data()
