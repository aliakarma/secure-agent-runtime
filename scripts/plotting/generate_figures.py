"""
Generate Publication-Quality Figures for Thesis
------------------------------------------------
Generates six high-quality PNG charts and heatmaps and saves them to docs/figures/.
"""

import os
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Set figure style for publication
sns.set_theme(style="whitegrid")
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.titlesize": 14,
    "legend.fontsize": 10
})

FIGURES_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

def generate_asr_comparison():
    fig, ax = plt.subplots(figsize=(7, 4.5))
    categories = ["Direct Injection", "Indirect Injection", "Memory Poisoning", "Multimodal Ingestion"]
    baseline_asr = [100.0, 100.0, 100.0, 100.0]
    secured_asr = [15.0, 15.0, 15.0, 0.0]
    
    x = np.arange(len(categories))
    width = 0.35
    
    rects1 = ax.bar(x - width/2, baseline_asr, width, label="Baseline (Unsecured)", color="#d9534f")
    rects2 = ax.bar(x + width/2, secured_asr, width, label="SECURED (Full Defenses)", color="#5cb85c")
    
    ax.set_ylabel("Attack Success Rate (ASR %)")
    ax.set_title("ASR Comparison across Ingestion Pathways")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=15)
    ax.set_ylim(0, 115)
    ax.legend()
    
    # Add labels on top of bars
    for rect in rects1:
        height = rect.get_height()
        ax.annotate(f"{height:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9)
                    
    for rect in rects2:
        height = rect.get_height()
        ax.annotate(f"{height:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9)
                    
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "asr_comparison_plot.png", dpi=300)
    plt.close(fig)
    print("Generated asr_comparison_plot.png")

def generate_tar_tradeoff():
    fig, ax1 = plt.subplots(figsize=(7.5, 4.5))
    
    configs = ["Config A\n(Baseline)", "Config B\n(Fast Heuristics)", "Config C\n(Secure Classifier)"]
    tar = [100.0, 100.0, 0.0]
    latency = [1469.70, 1254.25, 1669.69]
    
    color = "#1f77b4"
    ax1.set_xlabel("System Configuration")
    ax1.set_ylabel("Task Accuracy Retention (TAR %)", color=color)
    ax1.plot(configs, tar, color=color, marker="o", linewidth=2.5, markersize=8, label="TAR (%)")
    ax1.tick_params(axis="y", labelcolor=color)
    ax1.set_ylim(-10, 110)
    
    ax2 = ax1.twinx()
    color = "#ff7f0e"
    ax2.set_ylabel("Mean End-to-End Latency (ms)", color=color)
    ax2.bar(configs, latency, color=color, alpha=0.3, width=0.4, label="Latency (ms)")
    ax2.tick_params(axis="y", labelcolor=color)
    ax2.set_ylim(0, 2000)
    
    plt.title("Security/Usability Trade-off across Configurations")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "tar_tradeoff_plot.png", dpi=300)
    plt.close(fig)
    print("Generated tar_tradeoff_plot.png")

def generate_trust_degradation():
    fig, ax = plt.subplots(figsize=(7, 4.5))
    
    turns = [0, 1, 2, 3, 4, 5]
    benign = [1.00, 0.88, 0.88, 0.88, 0.88, 0.88]
    single = [1.00, 0.88, 0.88, 0.75, 0.75, 0.75]
    multi = [1.00, 0.88, 0.62, 0.62, 0.62, 0.62]
    
    ax.plot(turns, benign, marker="s", color="#2ca02c", linewidth=2, label="Benign Session (0 Attacks)")
    ax.plot(turns, single, marker="o", color="#ff7f0e", linewidth=2, label="Single-Attack Session (1 Attack)")
    ax.plot(turns, multi, marker="^", color="#d62728", linewidth=2, label="Multi-Attack Session (2 Attacks)")
    
    ax.set_xlabel("Conversation Turn")
    ax.set_ylabel("Dynamic Trust Score T(x)")
    ax.set_title("Stateful Trust Score Degradation Over Multi-Turn Interactions")
    ax.set_xticks(turns)
    ax.set_ylim(0.0, 1.1)
    ax.legend()
    
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "trust_degradation_curves.png", dpi=300)
    plt.close(fig)
    print("Generated trust_degradation_curves.png")

def generate_latency_comparison():
    fig, ax = plt.subplots(figsize=(8, 4.5))
    
    hooks = ["Hook 1\n(Pre-LLM)", "Hook 2\n(Visual)", "Hook 3\n(Post-Tool)", "Hook 4\n(Pre-Mem)", "Hook 5\n(Routing)", "Validator"]
    fast = [0.01, 1.31, 0.00, 0.00, 0.01, 0.05]
    secure = [65.02, 35.59, 79.75, 14.80, 66.86, 71.79]
    
    x = np.arange(len(hooks))
    width = 0.35
    
    rects1 = ax.bar(x - width/2, fast, width, label="Fast Heuristics", color="#3498db")
    rects2 = ax.bar(x + width/2, secure, width, label="Secure Classifier", color="#2c3e50")
    
    ax.set_ylabel("Inference Latency (ms)")
    ax.set_title("Hook Isolation Execution Latency Comparison")
    ax.set_xticks(x)
    ax.set_xticklabels(hooks)
    ax.set_yscale("log")  # Logarithmic scale due to order of magnitude difference
    ax.set_ylim(1e-3, 1e3)
    ax.legend()
    
    # Add values on top of bars
    for rect in rects1:
        height = rect.get_height()
        val = f"{height:.2f}" if height > 0 else "0.0"
        ax.annotate(val,
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
                    
    for rect in rects2:
        height = rect.get_height()
        ax.annotate(f"{height:.1f}",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 2),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8)
                    
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "latency_comparison_charts.png", dpi=300)
    plt.close(fig)
    print("Generated latency_comparison_charts.png")

def generate_confusion_matrices():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))
    
    # 1. R3 Secured Evaluation Confusion Matrix
    # TP=100, FN=0, FP=2, TN=98
    matrix_r3 = np.array([[100, 0], [2, 98]])
    sns.heatmap(matrix_r3, annot=True, fmt="d", cmap="Blues", cbar=False, ax=ax1,
                xticklabels=["Predicted Attack", "Predicted Benign"],
                yticklabels=["Actual Attack", "Actual Benign"])
    ax1.set_title("Phase R3 Secured Confusion Matrix")
    
    # 2. Evaluator Validation Matrix
    # Curated cases: 27 compromised, 27 defended
    # val_tm_3 (FP) and val_ii_3 (FN) are errors
    # TP = 26, FN = 1
    # FP = 1, TN = 26
    matrix_eval = np.array([[26, 1], [1, 26]])
    sns.heatmap(matrix_eval, annot=True, fmt="d", cmap="Greens", cbar=False, ax=ax2,
                xticklabels=["Predicted Attack", "Predicted Benign"],
                yticklabels=["Actual Attack", "Actual Benign"])
    ax2.set_title("Deterministic Policy Validation Matrix")
    
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "confusion_matrices.png", dpi=300)
    plt.close(fig)
    print("Generated confusion_matrices.png")

def generate_ablation_diagram():
    fig, ax = plt.subplots(figsize=(6, 4.5))
    
    configs = ["Config A\n(Baseline)", "Config B\n(Partial Defenses)", "Config C\n(Full SECURED)"]
    asr = [100.0, 100.0, 15.0]
    
    rects = ax.bar(configs, asr, width=0.4, color=["#e74c3c", "#e67e22", "#2ecc71"])
    
    ax.set_ylabel("Attack Success Rate (ASR %)")
    ax.set_title("ASR Reduction Across Ablated Configurations")
    ax.set_ylim(0, 115)
    
    # Add values on top of bars
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f"{height:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight="bold")
                    
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "ablation_diagrams.png", dpi=300)
    plt.close(fig)
    print("Generated ablation_diagrams.png")

def main():
    print("=== GENERATING PUBLICATION-QUALITY FIGURES ===")
    generate_asr_comparison()
    generate_tar_tradeoff()
    generate_trust_degradation()
    generate_latency_comparison()
    generate_confusion_matrices()
    generate_ablation_diagram()
    print("=== FIGURES GENERATED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
