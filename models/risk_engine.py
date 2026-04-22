"""
Combine IF anomaly score, RF attack probability, and optional alert severity into one risk score.
risk_score = w1 * anomaly + w2 * class_prob + w3 * severity (all 0-1).
"""

import numpy as np


class RiskEngine:
    def __init__(self, w1=0.4, w2=0.4, w3=0.2):
        self.w1 = w1
        self.w2 = w2
        self.w3 = w3

    def compute(self, anomaly_scores, attack_proba, severity_scores=None):
        """
        anomaly_scores: array shape (n,) in [0,1]
        attack_proba: array shape (n,) in [0,1]
        severity_scores: optional array (n,) in [0,1]; if None, use 0
        """
        a = np.asarray(anomaly_scores).ravel()
        p = np.asarray(attack_proba).ravel()
        s = np.asarray(severity_scores).ravel() if severity_scores is not None else np.zeros_like(a)
        if s.size != a.size:
            s = np.zeros_like(a)
        return np.clip(
            self.w1 * a + self.w2 * p + self.w3 * s,
            0.0,
            1.0,
        )

    def decision(self, risk_score, low_thresh=0.3, high_thresh=0.7):
        """Return LOW, MEDIUM, or HIGH."""
        if risk_score >= high_thresh:
            return "HIGH"
        if risk_score >= low_thresh:
            return "MEDIUM"
        return "LOW"
