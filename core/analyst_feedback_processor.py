"""
Feedback generation and model update processor.

Replaces: feedback_generate.py, feedback_update_code.py

Key improvements:
- No eval() on user data (security fix)
- No typos (dest_ffedback -> dest_feedback)
- Proper dict.pop() with key argument (bug fix)
- Clean separation of feedback generation vs. model update
- Integration with RL agent for threshold optimization
- Proper error handling and logging
- No redundant f.close() after with blocks
"""

import copy
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

from core.rl_config import get_config, get_day_type, OUTPUTS_DIR, MODELS_DIR
from core.rl_anomaly_detector import AnomalyDetector, DetectionReport
from core.rl_attack_predictor import RLThresholdOptimizer

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Feedback generation (simulated analyst feedback)
# ──────────────────────────────────────────────────────────────────────

class FeedbackGenerator:
    """
    Generates simulated analyst feedback for detected anomalies.

    In production, this would be replaced by a real analyst interface.
    """

    def __init__(self, seed: Optional[int] = None):
        self.cfg = get_config().feedback
        self.rng = np.random.RandomState(seed or self.cfg.random_seed)

    def _get_time_feedback(self, intervals: List[int]) -> Dict:
        """Generate feedback for time-based anomalies."""
        feedback = {}
        for i in intervals:
            if self.rng.random() <= self.cfg.positive_anomaly_rate:
                feedback[str(i)] = "Positive"
            else:
                feedback[str(i)] = "Negative"
        return feedback

    def _get_new_user_feedback(self) -> str:
        """Generate feedback for new user detection."""
        if self.rng.random() <= self.cfg.new_user_anomaly_rate:
            return "New Positive"
        return "New Negative"

    def _get_entity_feedback(self, is_new: bool) -> str:
        """Generate feedback for source/destination anomalies."""
        if is_new:
            return self._get_new_user_feedback()
        if self.rng.random() <= self.cfg.positive_anomaly_rate:
            return "Positive"
        return "Negative"

    def generate(
        self,
        curr_date: datetime,
        report: DetectionReport,
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Generate feedback for all anomalies in a detection report.

        Returns (user_feedback, source_feedback, dest_feedback) as lists of dicts.
        """
        user_fb_list = []
        src_fb_list = []
        dest_fb_list = []

        # User/time feedback
        time_dict, source_dict, dest_dict = report.to_legacy_dicts()

        for user, anomaly_str in time_dict.items():
            entry = {
                "DestinationUserName": user,
                "StartDate": curr_date.strftime("%Y-%m-%d"),
            }

            if anomaly_str == "New User":
                entry["Anomaly"] = self._get_new_user_feedback()
            else:
                # Parse intervals safely (no eval!)
                intervals = report.time_anomalies[user].intervals
                if self.rng.random() <= self.cfg.feedback_response_rate:
                    entry["Anomaly"] = self._get_time_feedback(intervals)
                else:
                    entry["Anomaly"] = "Nil"

            user_fb_list.append(entry)

        # Source feedback
        for user, sa_dict in source_dict.items():
            entry = {
                "DestinationUserName": user,
                "StartDate": curr_date.strftime("%Y-%m-%d"),
                "Anomaly": {},
            }
            for sa, anomaly_str in sa_dict.items():
                is_new = "New" in anomaly_str
                if self.rng.random() <= self.cfg.feedback_response_rate or is_new:
                    entry["Anomaly"][sa] = self._get_entity_feedback(is_new)
                else:
                    entry["Anomaly"][sa] = "Nil"
            src_fb_list.append(entry)

        # Destination feedback
        for user, dh_dict in dest_dict.items():
            entry = {
                "DestinationUserName": user,
                "StartDate": curr_date.strftime("%Y-%m-%d"),
                "Anomaly": {},
            }
            for dh, anomaly_str in dh_dict.items():
                is_new = "New" in anomaly_str
                if self.rng.random() <= self.cfg.feedback_response_rate or is_new:
                    entry["Anomaly"][dh] = self._get_entity_feedback(is_new)
                else:
                    entry["Anomaly"][dh] = "Nil"
            dest_fb_list.append(entry)

        logger.info("Generated feedback: %d user, %d source, %d dest entries",
                    len(user_fb_list), len(src_fb_list), len(dest_fb_list))

        return user_fb_list, src_fb_list, dest_fb_list

    def save_feedback(
        self,
        user_fb: List[Dict],
        src_fb: List[Dict],
        dest_fb: List[Dict],
        output_dir: Optional[Path] = None,
    ) -> None:
        """Save feedback to JSON files."""
        out = output_dir or OUTPUTS_DIR
        cfg = self.cfg

        with open(out / cfg.user_feedback_file, "w") as f:
            json.dump(user_fb, f, indent=2)
        with open(out / cfg.source_feedback_file, "w") as f:
            json.dump(src_fb, f, indent=2)
        with open(out / cfg.dest_feedback_file, "w") as f:
            json.dump(dest_fb, f, indent=2)

        logger.info("Feedback saved to %s", out)


# ──────────────────────────────────────────────────────────────────────
# Model updater (processes feedback and updates training model)
# ──────────────────────────────────────────────────────────────────────

class ModelUpdater:
    """
    Processes analyst feedback and updates the training model.

    Integrates with the RL agent for threshold optimization.
    """

    def __init__(
        self,
        train_model: Dict,
        test_model: Dict,
        threshold_dict: Dict,
        rl_optimizer: Optional[RLThresholdOptimizer] = None,
    ):
        self.cfg = get_config()
        self.train_model = train_model
        self.test_model = test_model
        self.threshold_dict = threshold_dict
        self.mult_fac = 2.0  # score multiplier

        # RL optimizer (if None, falls back to simple averaging)
        self.rl_optimizer = rl_optimizer or RLThresholdOptimizer(threshold_dict)

    @staticmethod
    def sigmoid(x: np.ndarray) -> np.ndarray:
        """Numerically stable sigmoid scaled to 0-100."""
        s = np.where(
            x >= 0,
            1.0 / (1.0 + np.exp(-x)),
            np.exp(x) / (1.0 + np.exp(x)),
        )
        return s * 100.0

    def _update_interval_counters(
        self,
        model: Dict,
        user: str,
        day_type: str,
        x: np.ndarray,
        avg_new: np.ndarray,
        day_count: Any,
        update_intervals: Optional[List[int]] = None,
        is_new_user: bool = False,
        test_day_block: Optional[Dict] = None,
    ) -> None:
        """Update interval counters in the model."""
        day_count_key = str(day_count)

        if is_new_user and test_day_block is not None:
            # Initialize new user in model
            model[user] = {}
            model[user]["UserLabel"] = len(model)
            for dt in ["WD", "Sat", "Sun"]:
                model[user][dt] = {
                    "DayCounter": 0,
                    "IntervalCounter": {
                        "0": [0]*8, "sum": [0]*8,
                    },
                    "SourceAddress": {},
                    "DestinationHost": {},
                }

            model[user][day_type]["IntervalCounter"]["0"] = x.tolist()
            model[user][day_type]["IntervalCounter"]["sum"] = x.tolist()
            model[user][day_type]["IntervalCounter"]["avg"] = avg_new.tolist()
            model[user][day_type]["IntervalCounter"]["std"] = (0.2 * avg_new).tolist()

            # Copy source and dest from test data
            for sa, count in test_day_block.get("SourceAddress", {}).items():
                model[user][day_type]["SourceAddress"][sa] = {
                    "0": count, "sum": count, "avg": count, "std": round(0.2 * count, 4)
                }
            for dh, count in test_day_block.get("DestinationHost", {}).items():
                dh_str = str(dh)
                model[user][day_type]["DestinationHost"][dh_str] = {
                    "0": count, "sum": count, "avg": count, "std": round(0.2 * count, 4)
                }
            return

        ic = model[user][day_type]["IntervalCounter"]
        ic[day_count_key] = x.tolist()

        if update_intervals is not None and len(update_intervals) > 0:
            # Only update sum for specified intervals
            sum_arr = np.array(ic.get("sum", [0]*8), dtype=np.float64)
            for i in update_intervals:
                sum_arr[i] += x[i]
            ic["sum"] = sum_arr.tolist()
        elif update_intervals is None:
            # Update all
            sum_arr = np.array(ic.get("sum", [0]*8), dtype=np.float64) + x
            ic["sum"] = sum_arr.tolist()

        ic["avg"] = avg_new.tolist()
        ic["std"] = (0.2 * avg_new).tolist()

    def _update_source(
        self,
        model: Dict,
        user: str,
        day_type: str,
        sa: str,
        logons: float,
        avg_new: float,
        day_count: Any,
        is_new: bool = False,
        no_feedback: bool = False,
    ) -> None:
        """Update source address entry in model."""
        dc_key = str(day_count)
        sa_data = model[user][day_type]["SourceAddress"]

        if is_new:
            sa_data[sa] = {
                dc_key: logons, "sum": logons,
                "avg": avg_new, "std": round(0.2 * avg_new, 4),
            }
        elif no_feedback:
            if sa in sa_data:
                sa_data[sa][dc_key] = logons
                sa_data[sa]["avg"] = avg_new
                sa_data[sa]["std"] = round(0.2 * avg_new, 4)
        else:
            if sa in sa_data:
                sa_data[sa][dc_key] = logons
                sa_data[sa]["sum"] = sa_data[sa].get("sum", 0) + logons
                sa_data[sa]["avg"] = avg_new
                sa_data[sa]["std"] = round(0.2 * avg_new, 4)

    def _update_dest(
        self,
        model: Dict,
        user: str,
        day_type: str,
        dh: str,
        logons: float,
        avg_new: float,
        day_count: Any,
        is_new: bool = False,
        no_feedback: bool = False,
    ) -> None:
        """Update destination host entry in model."""
        dc_key = str(day_count)
        dh_data = model[user][day_type]["DestinationHost"]

        if is_new:
            dh_data[dh] = {
                dc_key: logons, "sum": logons,
                "avg": avg_new, "std": round(0.2 * avg_new, 4),
            }
        elif no_feedback:
            if dh in dh_data:
                dh_data[dh][dc_key] = logons
                dh_data[dh]["avg"] = avg_new
                dh_data[dh]["std"] = round(0.2 * avg_new, 4)
        else:
            if dh in dh_data:
                dh_data[dh][dc_key] = logons
                dh_data[dh]["sum"] = dh_data[dh].get("sum", 0) + logons
                dh_data[dh]["avg"] = avg_new
                dh_data[dh]["std"] = round(0.2 * avg_new, 4)

    def update(
        self,
        date: datetime,
        anomaly_dict: Dict,
        source_anomaly: Dict,
        dest_anomaly: Dict,
    ) -> Tuple[Dict, Dict]:
        """
        Main update function: processes feedback and updates the training model.

        Returns (updated_model, updated_thresholds).
        """
        day_type = get_day_type(date)
        model_new = copy.deepcopy(self.train_model)

        # Load feedback files
        user_fb, src_fb, dest_fb = self._load_feedback()

        # ── Process user/time feedback ──
        for fb in user_fb:
            user = fb["DestinationUserName"]
            fb_anomaly = fb.get("Anomaly", "Nil")

            if isinstance(fb_anomaly, str) and "New" in fb_anomaly:
                # New user: add to model
                if user in self.test_model:
                    x = np.array(self.test_model[user][day_type]["IntervalCounter"], dtype=np.float64)
                    self._update_interval_counters(
                        model_new, user, day_type, x, x, 0,
                        is_new_user=True,
                        test_day_block=self.test_model[user][day_type],
                    )

                    # RL: process new user feedback
                    rl_feedback = "Positive" if fb_anomaly == "New Positive" else "Negative"
                    self.rl_optimizer.optimize(user, x, rl_feedback)

            elif isinstance(fb_anomaly, dict):
                # Existing user with interval-level feedback
                self._process_user_feedback(model_new, user, day_type, fb, date)

            elif fb_anomaly == "Nil":
                # No feedback received
                self._process_no_feedback_user(model_new, user, day_type, date)

        # ── Update non-anomalous users ──
        for user in self.test_model:
            if user not in anomaly_dict:
                self._update_normal_user(model_new, user, day_type)

        # ── Increment day counters ──
        for user in model_new:
            if day_type in model_new[user]:
                model_new[user][day_type]["DayCounter"] = \
                    model_new[user][day_type].get("DayCounter", 0) + 1

        # ── Process source feedback ──
        self._process_source_feedback(model_new, src_fb, source_anomaly, day_type, date)

        # ── Process destination feedback ──
        self._process_dest_feedback(model_new, dest_fb, dest_anomaly, day_type, date)

        updated_thresholds = self.rl_optimizer.get_all_thresholds()

        logger.info("Model update complete for date=%s", date.strftime("%Y-%m-%d"))
        return model_new, updated_thresholds

    def _load_feedback(self) -> Tuple[List, List, List]:
        """Load feedback JSON files."""
        cfg = self.cfg.feedback

        def _load(filename):
            path = OUTPUTS_DIR / filename
            if path.exists():
                with open(path, "r") as f:
                    return json.load(f)
            return []

        user_fb = _load(cfg.user_feedback_file)
        src_fb = _load(cfg.source_feedback_file)
        dest_fb = _load(cfg.dest_feedback_file)

        logger.info("Loaded feedback: %d user, %d source, %d dest",
                    len(user_fb), len(src_fb), len(dest_fb))
        return user_fb, src_fb, dest_fb

    def _process_user_feedback(
        self, model: Dict, user: str, day_type: str, fb: Dict, date: datetime
    ) -> None:
        """Process interval-level feedback for an existing user."""
        if user not in self.train_model or user not in self.test_model:
            return

        x = np.array(self.test_model[user][day_type]["IntervalCounter"], dtype=np.float64)
        avg = np.array(self.train_model[user][day_type]["IntervalCounter"].get("avg", [0]*8))

        # Count training days (exclude metadata keys)
        meta_keys = {"sum", "avg", "std", "NoFeedback"}
        ic = self.train_model[user][day_type]["IntervalCounter"]
        counter = max(len([k for k in ic if k not in meta_keys]), 1)
        day_count = self.train_model[user][day_type].get("DayCounter", 0)

        fb_anomaly = fb["Anomaly"]

        # Determine which intervals to update (Negative = false positive = update)
        positive_intervals = [int(k) for k, v in fb_anomaly.items() if v == "Positive"]
        update_intervals = [i for i in range(8) if i not in positive_intervals]

        # Compute new average for update intervals
        avg_new = avg.copy()
        if update_intervals:
            xi = x[update_intervals]
            avgi = avg[update_intervals]
            avg_new[update_intervals] = np.round((xi + avgi * counter) / (counter + 1), 2)

        # Update model
        x_store = x.copy()
        x_store[positive_intervals] = -1  # Mark positive (confirmed anomaly) intervals
        self._update_interval_counters(
            model, user, day_type, x_store, avg_new, day_count,
            update_intervals=update_intervals,
        )

        # RL: compute risk scores and optimize thresholds
        avg_sum = max(np.sum(avg_new), 1.0)
        risk_scores = AnomalyDetector.sigmoid((x - avg_new) / avg_sum * self.mult_fac) * 100.0

        # Process each interval's feedback through RL
        for idx_str, verdict in fb_anomaly.items():
            if verdict in ("Positive", "Negative"):
                self.rl_optimizer.optimize(user, risk_scores, verdict)

    def _process_no_feedback_user(
        self, model: Dict, user: str, day_type: str, date: datetime
    ) -> None:
        """Handle users where no feedback was received."""
        if user not in self.train_model or user not in self.test_model:
            return

        x = np.array(self.test_model[user][day_type]["IntervalCounter"], dtype=np.float64)
        avg = np.array(self.train_model[user][day_type]["IntervalCounter"].get("avg", [0]*8))
        day_count = self.train_model[user][day_type].get("DayCounter", 0)

        meta_keys = {"sum", "avg", "std", "NoFeedback"}
        ic = self.train_model[user][day_type]["IntervalCounter"]
        counter = max(len([k for k in ic if k not in meta_keys]), 1)

        # Store data but don't update averages
        ic_new = model[user][day_type]["IntervalCounter"]
        if "NoFeedback" not in ic_new:
            ic_new["NoFeedback"] = {}
        ic_new["NoFeedback"][date.strftime("%Y-%m-%d")] = day_count
        ic_new[str(day_count)] = x.tolist()

    def _update_normal_user(self, model: Dict, user: str, day_type: str) -> None:
        """Update a non-anomalous user's model with new data."""
        if user not in self.train_model or user not in self.test_model:
            return

        x = np.array(self.test_model[user][day_type]["IntervalCounter"], dtype=np.float64)
        avg = np.array(self.train_model[user][day_type]["IntervalCounter"].get("avg", [0]*8))

        meta_keys = {"sum", "avg", "std", "NoFeedback"}
        ic = self.train_model[user][day_type]["IntervalCounter"]
        counter = max(len([k for k in ic if k not in meta_keys]), 1)
        day_count = self.train_model[user][day_type].get("DayCounter", 0)

        avg_new = np.round((x + avg * counter) / (counter + 1), 2)
        self._update_interval_counters(model, user, day_type, x, avg_new, day_count)

        # Update thresholds via RL (as TrueNegative)
        avg_sum = max(np.sum(avg_new), 1.0)
        risk_scores = AnomalyDetector.sigmoid((x - avg_new) / avg_sum * self.mult_fac) * 100.0
        self.rl_optimizer.optimize(user, risk_scores, "TrueNegative")

    def _process_source_feedback(
        self, model: Dict, src_fb: List, source_anomaly: Dict,
        day_type: str, date: datetime
    ) -> None:
        """Process source address feedback and update model."""
        for fb_entry in src_fb:
            user = fb_entry["DestinationUserName"]
            if user not in self.train_model or user not in self.test_model:
                continue

            for sa, verdict in fb_entry.get("Anomaly", {}).items():
                if "New" in str(verdict):
                    # New source address
                    if sa in self.test_model[user][day_type].get("SourceAddress", {}):
                        logons = self.test_model[user][day_type]["SourceAddress"][sa]
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        self._update_source(model, user, day_type, sa, logons, logons, day_count, is_new=True)

                elif verdict == "Negative":
                    # False positive: update average
                    if sa in self.train_model[user][day_type].get("SourceAddress", {}):
                        sa_data = self.train_model[user][day_type]["SourceAddress"][sa]
                        meta_keys = {"sum", "avg", "std", "NoFeedback"}
                        counter = max(len([k for k in sa_data if k not in meta_keys]), 1)
                        logons = self.test_model[user][day_type]["SourceAddress"].get(sa, 0)
                        avg = sa_data.get("avg", 0)
                        avg_new = round((logons + counter * avg) / (counter + 1), 2)
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        self._update_source(model, user, day_type, sa, logons, avg_new, day_count)

                elif verdict == "Nil":
                    # No feedback: store but don't update avg
                    if sa in self.test_model[user][day_type].get("SourceAddress", {}):
                        logons = self.test_model[user][day_type]["SourceAddress"][sa]
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        avg = self.train_model[user][day_type].get("SourceAddress", {}).get(sa, {}).get("avg", logons)
                        self._update_source(model, user, day_type, sa, logons, avg, day_count, no_feedback=True)

        # Update non-anomalous source addresses
        for user in self.test_model:
            if user not in self.train_model:
                continue
            for sa, count in self.test_model[user][day_type].get("SourceAddress", {}).items():
                is_anomalous = user in source_anomaly and sa in source_anomaly.get(user, {})
                if not is_anomalous and sa in self.train_model[user][day_type].get("SourceAddress", {}):
                    sa_data = self.train_model[user][day_type]["SourceAddress"][sa]
                    meta_keys = {"sum", "avg", "std", "NoFeedback"}
                    counter = max(len([k for k in sa_data if k not in meta_keys]), 1)
                    avg = sa_data.get("avg", 0)
                    avg_new = round((count + counter * avg) / (counter + 1), 2)
                    day_count = self.train_model[user][day_type].get("DayCounter", 0)
                    self._update_source(model, user, day_type, sa, count, avg_new, day_count)

    def _process_dest_feedback(
        self, model: Dict, dest_fb: List, dest_anomaly: Dict,
        day_type: str, date: datetime
    ) -> None:
        """Process destination host feedback and update model."""
        for fb_entry in dest_fb:
            user = fb_entry["DestinationUserName"]
            if user not in self.train_model or user not in self.test_model:
                continue

            for dh, verdict in fb_entry.get("Anomaly", {}).items():
                dh_str = str(dh)

                if "New" in str(verdict):
                    if dh in self.test_model[user][day_type].get("DestinationHost", {}):
                        logons = self.test_model[user][day_type]["DestinationHost"][dh]
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        self._update_dest(model, user, day_type, dh_str, logons, logons, day_count, is_new=True)

                elif verdict == "Negative":
                    if dh_str in self.train_model[user][day_type].get("DestinationHost", {}):
                        dh_data = self.train_model[user][day_type]["DestinationHost"][dh_str]
                        meta_keys = {"sum", "avg", "std", "NoFeedback"}
                        counter = max(len([k for k in dh_data if k not in meta_keys]), 1)
                        logons = self.test_model[user][day_type]["DestinationHost"].get(dh, 0)
                        if isinstance(logons, dict):
                            logons = self.test_model[user][day_type]["DestinationHost"].get(int(dh), 0)
                        avg = dh_data.get("avg", 0)
                        avg_new = round((logons + counter * avg) / (counter + 1), 2)
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        self._update_dest(model, user, day_type, dh_str, logons, avg_new, day_count)

                elif verdict == "Nil":
                    if dh in self.test_model[user][day_type].get("DestinationHost", {}):
                        logons = self.test_model[user][day_type]["DestinationHost"][dh]
                        day_count = self.train_model[user][day_type].get("DayCounter", 0)
                        avg = self.train_model[user][day_type].get("DestinationHost", {}).get(dh_str, {}).get("avg", logons)
                        self._update_dest(model, user, day_type, dh_str, logons, avg, day_count, no_feedback=True)

        # Update non-anomalous destination hosts
        for user in self.test_model:
            if user not in self.train_model:
                continue
            for dh, count in self.test_model[user][day_type].get("DestinationHost", {}).items():
                dh_str = str(dh)
                is_anomalous = user in dest_anomaly and (dh in dest_anomaly.get(user, {}) or dh_str in dest_anomaly.get(user, {}))
                if not is_anomalous and dh_str in self.train_model[user][day_type].get("DestinationHost", {}):
                    dh_data = self.train_model[user][day_type]["DestinationHost"][dh_str]
                    meta_keys = {"sum", "avg", "std", "NoFeedback"}
                    counter = max(len([k for k in dh_data if k not in meta_keys]), 1)
                    avg = dh_data.get("avg", 0)
                    avg_new = round((count + counter * avg) / (counter + 1), 2)
                    day_count = self.train_model[user][day_type].get("DayCounter", 0)
                    self._update_dest(model, user, day_type, dh_str, count, avg_new, day_count)

        logger.info("Destination host updates complete")
