"""
Modern anomaly detection engine.

Replaces: User_logon_anomaly_code.py

Key improvements:
- Combines sigmoid-based statistical scoring with Isolation Forest ensemble
- Proper numpy vectorization
- No code duplication across anomaly types
- Clean API with typed returns
- Structured anomaly results (not just string concatenation)
- Supports both real-time (streaming) and batch (end-of-file) detection
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

from core.rl_config import get_config

logger = logging.getLogger(__name__)

# Optional: Isolation Forest from scikit-learn
try:
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn not installed; Isolation Forest disabled.")


# ──────────────────────────────────────────────────────────────────────
# Anomaly result data structures
# ──────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    """Structured result for a single anomaly detection."""
    user: str
    anomaly_type: str          # "time", "source", "destination", "new_user"
    detail: str                # human-readable description
    risk_score: float = 0.0    # 0-100 scale
    intervals: List[int] = field(default_factory=list)
    entity: str = ""           # source address or dest host involved
    is_new: bool = False       # whether this is a new user/source/dest


@dataclass
class DetectionReport:
    """Aggregated detection results for one detection pass."""
    time_anomalies: Dict[str, AnomalyResult] = field(default_factory=dict)
    source_anomalies: Dict[str, Dict[str, AnomalyResult]] = field(default_factory=dict)
    dest_anomalies: Dict[str, Dict[str, AnomalyResult]] = field(default_factory=dict)
    new_users: List[str] = field(default_factory=list)

    def to_legacy_dicts(self) -> Tuple[Dict, Dict, Dict]:
        """Convert to legacy format for backward compatibility."""
        time_dict = {}
        for user, result in self.time_anomalies.items():
            if result.is_new:
                time_dict[user] = "New User"
            else:
                time_dict[user] = f"Logon time, intervals: {result.intervals}"

        source_dict = {}
        for user, sa_results in self.source_anomalies.items():
            source_dict[user] = {}
            for sa, result in sa_results.items():
                if result.is_new:
                    source_dict[user][sa] = "New Source Address"
                else:
                    source_dict[user][sa] = f"Source Address Anomaly {result.risk_score:.1f}"

        dest_dict = {}
        for user, dh_results in self.dest_anomalies.items():
            dest_dict[user] = {}
            for dh, result in dh_results.items():
                if result.is_new:
                    dest_dict[user][dh] = "New Destination Host"
                else:
                    dest_dict[user][dh] = f"Destination Host Anomaly {result.risk_score:.1f}"

        return time_dict, source_dict, dest_dict


# ──────────────────────────────────────────────────────────────────────
# Anomaly Detector
# ──────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Multi-dimensional anomaly detection engine.

    Detects anomalies in:
    1. Logon time patterns (interval-based)
    2. Source IP addresses
    3. Destination hosts
    4. New/unknown users

    Uses:
    - Sigmoid-based risk scoring (statistical baseline)
    - Optional Isolation Forest ensemble (unsupervised ML)
    """

    def __init__(
        self,
        baseline_model: Dict,
        current_model: Dict,
        threshold_dict: Optional[Dict] = None,
    ):
        """
        Args:
            baseline_model: Trained model with avg/std statistics.
            current_model: Current observation model (test data).
            threshold_dict: Per-user anomaly thresholds {user: [lower, upper]}.
        """
        self.cfg = get_config().detection
        self.baseline = baseline_model
        self.current = current_model
        self.thresholds = threshold_dict or {}
        self.mult_fac = 100.0 / self.cfg.percent_criteria

        # Isolation Forest instance (trained lazily)
        self._iso_forest: Optional[Any] = None

        # Interval labels for logging
        n = self.cfg.percent_criteria  # reuse num_intervals from data config
        hours = get_config().data.hours_per_interval
        num_int = get_config().data.num_intervals
        self._interval_labels = [
            f"{i*hours}-{(i+1)*hours} hrs" for i in range(num_int)
        ]

    # ── Utility ──────────────────────────────────────────────────────

    @staticmethod
    def sigmoid(x: np.ndarray) -> np.ndarray:
        """Numerically stable sigmoid."""
        return np.where(
            x >= 0,
            1.0 / (1.0 + np.exp(-x)),
            np.exp(x) / (1.0 + np.exp(x)),
        )

    def _get_threshold(self, user: str) -> List[float]:
        """Get or initialize threshold for a user."""
        if user not in self.thresholds:
            self.thresholds[user] = list(self.cfg.default_threshold)
        return self.thresholds[user]

    def _compute_risk_scores(
        self, x: np.ndarray, avg: np.ndarray
    ) -> np.ndarray:
        """Compute risk scores from current values and baseline averages."""
        avg_sum = max(np.sum(avg), self.cfg.min_avg_sum)
        score = (x - avg) / avg_sum * self.mult_fac
        return self.sigmoid(score) * 100.0

    # ── Isolation Forest ─────────────────────────────────────────────

    def _train_isolation_forest(self) -> None:
        """Train Isolation Forest on baseline model features."""
        if not HAS_SKLEARN or not self.cfg.use_isolation_forest:
            return

        features = []
        for user, data in self.baseline.items():
            for day_type in ["WD", "Sat", "Sun"]:
                day_block = data.get(day_type, {})
                ic = day_block.get("IntervalCounter", {})
                avg = ic.get("avg")
                if avg:
                    features.append(avg)

        if len(features) < 10:
            logger.warning("Insufficient data for Isolation Forest (%d samples)", len(features))
            return

        X = np.array(features, dtype=np.float64)
        self._iso_forest = IsolationForest(
            n_estimators=self.cfg.isolation_n_estimators,
            contamination=self.cfg.isolation_contamination,
            random_state=self.cfg.isolation_random_state,
        )
        self._iso_forest.fit(X)
        logger.info("Isolation Forest trained on %d samples", len(features))

    def _iso_forest_score(self, x: np.ndarray) -> float:
        """Get Isolation Forest anomaly score for a feature vector. Lower = more anomalous."""
        if self._iso_forest is None:
            return 0.0
        # score_samples returns negative for anomalies
        score = self._iso_forest.score_samples(x.reshape(1, -1))[0]
        # Convert to 0-100 scale: more negative = higher anomaly score
        return max(0.0, min(100.0, (1.0 - score) * 50.0))

    # ── Time-based anomaly detection ─────────────────────────────────

    def detect_time_anomalies(
        self,
        day_type: str,
        prev_interval: Optional[Dict[str, int]] = None,
        eof: bool = False,
    ) -> Tuple[Dict[str, AnomalyResult], Dict[str, int]]:
        """
        Detect logon time anomalies for all users.

        Args:
            day_type: "WD", "Sat", or "Sun"
            prev_interval: Tracking dict for streaming mode (None for batch)
            eof: Whether we've reached end of file (batch mode)

        Returns:
            (anomaly_results, updated_prev_interval)
        """
        if prev_interval is None:
            prev_interval = {}

        # Lazily train isolation forest
        if self._iso_forest is None and self.cfg.use_isolation_forest:
            self._train_isolation_forest()

        results: Dict[str, AnomalyResult] = {}

        for user in self.current:
            threshold = self._get_threshold(user)

            # New user detection
            if user not in self.baseline:
                results[user] = AnomalyResult(
                    user=user,
                    anomaly_type="new_user",
                    detail="New User",
                    risk_score=100.0,
                    is_new=True,
                )
                continue

            user_current = self.current[user].get(day_type, {})
            user_baseline = self.baseline[user].get(day_type, {})

            x = np.array(user_current.get("IntervalCounter", [0]*8), dtype=np.float64)
            avg = np.array(user_baseline.get("IntervalCounter", {}).get("avg", [0]*8), dtype=np.float64)
            curr_interval = user_current.get("Interval", 0)

            risk_scores = self._compute_risk_scores(x, avg)

            # Isolation Forest ensemble score
            iso_score = self._iso_forest_score(x) if self._iso_forest else 0.0

            if eof:
                # Check all intervals at end of file
                anomalous = np.where(
                    np.logical_or(risk_scores > threshold[1], risk_scores < threshold[0])
                )[0]
            else:
                # Streaming: check completed intervals
                if user not in prev_interval:
                    prev_interval[user] = curr_interval

                if curr_interval > prev_interval[user]:
                    check_range = slice(0, -8 + curr_interval) if curr_interval < 8 else slice(None)
                    rs_check = risk_scores[check_range]
                    anomalous = np.where(
                        np.logical_or(rs_check > threshold[1], rs_check < threshold[0])
                    )[0]
                    prev_interval[user] = curr_interval
                else:
                    # Only check current interval
                    if risk_scores[curr_interval] > threshold[1]:
                        anomalous = np.array([curr_interval])
                    else:
                        anomalous = np.array([], dtype=int)

            if len(anomalous) > 0:
                # Combine statistical + IF scores
                max_risk = float(np.max(risk_scores[anomalous]))
                combined_score = max_risk
                if iso_score > 0:
                    combined_score = 0.7 * max_risk + 0.3 * iso_score

                interval_labels = [self._interval_labels[i] for i in anomalous]
                results[user] = AnomalyResult(
                    user=user,
                    anomaly_type="time",
                    detail=f"Logon time anomaly at {interval_labels}",
                    risk_score=combined_score,
                    intervals=anomalous.tolist(),
                )
                logger.info("Time anomaly: user=%s intervals=%s score=%.1f",
                           user, interval_labels, combined_score)

        return results, prev_interval

    # ── Source address anomaly detection ──────────────────────────────

    def detect_source_anomalies(
        self, day_type: str, eof: bool = False
    ) -> Dict[str, Dict[str, AnomalyResult]]:
        """Detect source IP address anomalies for all users."""
        results: Dict[str, Dict[str, AnomalyResult]] = {}

        for user in self.current:
            if user not in self.baseline:
                continue

            user_current = self.current[user].get(day_type, {})
            user_baseline = self.baseline[user].get(day_type, {})

            avg_sum = max(
                np.sum(np.array(user_baseline.get("IntervalCounter", {}).get("avg", [0]*8))),
                self.cfg.min_avg_sum,
            )

            user_results: Dict[str, AnomalyResult] = {}

            for sa, count in user_current.get("SourceAddress", {}).items():
                if sa in user_baseline.get("SourceAddress", {}):
                    sa_baseline = user_baseline["SourceAddress"][sa]
                    sa_avg = sa_baseline.get("avg", 0)
                    x = float(count)

                    score = (x - sa_avg) / avg_sum
                    risk_score = float(self.sigmoid(np.array([score]))[0] * 100.0)

                    if eof:
                        is_anomalous = risk_score > self.cfg.source_upper_threshold or \
                                       risk_score < self.cfg.source_lower_threshold
                    else:
                        is_anomalous = risk_score > self.cfg.source_upper_threshold

                    if is_anomalous:
                        user_results[sa] = AnomalyResult(
                            user=user,
                            anomaly_type="source",
                            detail=f"Source Address Anomaly (score={risk_score:.1f})",
                            risk_score=risk_score,
                            entity=sa,
                        )
                        logger.info("Source anomaly: user=%s sa=%s score=%.1f",
                                   user, sa, risk_score)
                else:
                    user_results[sa] = AnomalyResult(
                        user=user,
                        anomaly_type="source",
                        detail="New Source Address",
                        risk_score=100.0,
                        entity=sa,
                        is_new=True,
                    )
                    logger.info("New source address: user=%s sa=%s", user, sa)

            if user_results:
                results[user] = user_results

        return results

    # ── Destination host anomaly detection ────────────────────────────

    def detect_dest_anomalies(
        self, day_type: str, eof: bool = False
    ) -> Dict[str, Dict[str, AnomalyResult]]:
        """Detect destination host anomalies for all users."""
        results: Dict[str, Dict[str, AnomalyResult]] = {}

        for user in self.current:
            if user not in self.baseline:
                continue

            user_current = self.current[user].get(day_type, {})
            user_baseline = self.baseline[user].get(day_type, {})

            avg_sum = max(
                np.sum(np.array(user_baseline.get("IntervalCounter", {}).get("avg", [0]*8))),
                self.cfg.min_avg_sum,
            )

            user_results: Dict[str, AnomalyResult] = {}

            for dh, count in user_current.get("DestinationHost", {}).items():
                dh_str = str(dh)
                if dh_str in user_baseline.get("DestinationHost", {}):
                    dh_baseline = user_baseline["DestinationHost"][dh_str]
                    dh_avg = dh_baseline.get("avg", 0)
                    x = float(count)

                    score = (x - dh_avg) / avg_sum
                    risk_score = float(self.sigmoid(np.array([score]))[0] * 100.0)

                    if eof:
                        is_anomalous = risk_score > self.cfg.dest_upper_threshold or \
                                       risk_score < self.cfg.dest_lower_threshold
                    else:
                        is_anomalous = risk_score > self.cfg.dest_upper_threshold

                    if is_anomalous:
                        user_results[dh_str] = AnomalyResult(
                            user=user,
                            anomaly_type="destination",
                            detail=f"Destination Host Anomaly (score={risk_score:.1f})",
                            risk_score=risk_score,
                            entity=dh_str,
                        )
                        logger.info("Dest anomaly: user=%s dh=%s score=%.1f",
                                   user, dh_str, risk_score)
                else:
                    user_results[dh_str] = AnomalyResult(
                        user=user,
                        anomaly_type="destination",
                        detail="New Destination Host",
                        risk_score=100.0,
                        entity=dh_str,
                        is_new=True,
                    )
                    logger.info("New dest host: user=%s dh=%s", user, dh_str)

            if user_results:
                results[user] = user_results

        return results

    # ── Full detection pass ──────────────────────────────────────────

    def run_detection(
        self,
        day_type: str,
        prev_interval: Optional[Dict[str, int]] = None,
        eof: bool = False,
    ) -> Tuple[DetectionReport, Dict[str, int]]:
        """
        Run full anomaly detection across all dimensions.

        Returns (DetectionReport, updated_prev_interval).
        """
        logger.info("Running detection pass (day_type=%s, eof=%s)", day_type, eof)

        time_results, prev_interval = self.detect_time_anomalies(day_type, prev_interval, eof)
        source_results = self.detect_source_anomalies(day_type, eof)
        dest_results = self.detect_dest_anomalies(day_type, eof)

        new_users = [u for u, r in time_results.items() if r.is_new]

        report = DetectionReport(
            time_anomalies=time_results,
            source_anomalies=source_results,
            dest_anomalies=dest_results,
            new_users=new_users,
        )

        total = len(time_results) + sum(len(v) for v in source_results.values()) + \
                sum(len(v) for v in dest_results.values())
        logger.info("Detection complete: %d total anomalies (%d time, %d source users, %d dest users, %d new)",
                    total, len(time_results), len(source_results), len(dest_results), len(new_users))

        return report, prev_interval
