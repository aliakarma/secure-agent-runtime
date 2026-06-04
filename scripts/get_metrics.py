import pandas as pd
import os

print("--- BASELINE METRICS ---")
if os.path.exists('datasets/baseline_metrics.csv'):
    df = pd.read_csv('datasets/baseline_metrics.csv')
    print(df.groupby('type')['is_success'].mean() * 100)
    print("Overall ASR:", df['is_success'].mean() * 100)
else:
    print("Not found.")

print("\n--- ABLATION CONFIG A METRICS ---")
if os.path.exists('datasets/results_config_A.csv'):
    df_a = pd.read_csv('datasets/results_config_A.csv')
    print(df_a.groupby('type')['is_success'].mean() * 100)
    print("Overall ASR:", df_a['is_success'].mean() * 100)
else:
    print("Not found.")
