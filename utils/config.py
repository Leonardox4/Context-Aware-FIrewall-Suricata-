"""
Simple config: paths, weights, thresholds. No external dependency.
"""

from pathlib import Path

# Default weights for risk score: w1*anomaly + w2*class_prob + w3*severity
DEFAULT_W1 = 0.4
DEFAULT_W2 = 0.4
DEFAULT_W3 = 0.2

# Decision thresholds (risk in [0,1])
LOW_THRESH = 0.3
HIGH_THRESH = 0.7

# Training defaults
DEFAULT_IF_CONTAMINATION = 0.1
DEFAULT_IF_ESTIMATORS = 100
DEFAULT_RF_ESTIMATORS = 100
DEFAULT_RF_MAX_DEPTH = 12
DEFAULT_TRAIN_TEST_RATIO = 0.2
DEFAULT_RANDOM_STATE = 42

# Chunk size for large CIC CSV
DEFAULT_CHUNK_ROWS = 50_000

# Chunk size for eve.json streaming (training and inference)
DEFAULT_CHUNK_EVE = 50_000
