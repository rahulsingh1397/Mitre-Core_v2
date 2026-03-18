"""
Deep Q-Network (DQN) Reinforcement Learning agent for adaptive threshold optimization.

This replaces the simple threshold averaging in the original code with a proper
RL formulation:

- **State**: [mean_risk_score, std_risk_score, current_lower_threshold,
              current_upper_threshold, false_positive_rate, detection_rate]
- **Actions**: 0=no_change, 1=widen_thresholds, 2=narrow_thresholds,
               3=shift_up, 4=shift_down
- **Reward**: Based on feedback (TP=+1, TN=+0.5, FP=-1, FN=-2)

Uses Double DQN with experience replay for stable learning.
Falls back to a simple rule-based agent if PyTorch is not available.
"""

import logging
import random
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from core.rl_config import get_config

logger = logging.getLogger(__name__)

# Optional PyTorch import
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not installed; using rule-based fallback agent.")


# ──────────────────────────────────────────────────────────────────────
# Experience replay buffer
# ──────────────────────────────────────────────────────────────────────

@dataclass
class Experience:
    """Single experience tuple for replay buffer."""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class ReplayBuffer:
    """Fixed-size experience replay buffer with uniform sampling."""

    def __init__(self, capacity: int):
        self.buffer = deque(maxlen=capacity)

    def push(self, exp: Experience) -> None:
        self.buffer.append(exp)

    def sample(self, batch_size: int) -> List[Experience]:
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))

    def __len__(self) -> int:
        return len(self.buffer)


# ──────────────────────────────────────────────────────────────────────
# DQN Network (PyTorch)
# ──────────────────────────────────────────────────────────────────────

if HAS_TORCH:
    class DQNetwork(nn.Module):
        """Deep Q-Network with configurable hidden layers."""

        def __init__(self, state_dim: int, action_dim: int, hidden_dims: List[int]):
            super().__init__()
            layers = []
            prev_dim = state_dim
            for h_dim in hidden_dims:
                layers.append(nn.Linear(prev_dim, h_dim))
                layers.append(nn.ReLU())
                layers.append(nn.LayerNorm(h_dim))
                prev_dim = h_dim
            layers.append(nn.Linear(prev_dim, action_dim))
            self.network = nn.Sequential(*layers)

        def forward(self, x):
            return self.network(x)


# ──────────────────────────────────────────────────────────────────────
# Threshold Environment
# ──────────────────────────────────────────────────────────────────────

class ThresholdEnv:
    """
    RL environment for threshold optimization.

    State: [mean_risk, std_risk, lower_th, upper_th, fp_rate, detection_rate]
    Actions: 0=noop, 1=widen, 2=narrow, 3=shift_up, 4=shift_down
    """

    def __init__(self, initial_threshold: List[float]):
        self.cfg = get_config().rl
        self.lower = initial_threshold[0]
        self.upper = initial_threshold[1]
        self.step_size = self.cfg.threshold_step

        # Tracking metrics
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0

    def get_state(self, risk_scores: np.ndarray) -> np.ndarray:
        """Build state vector from current risk scores and thresholds."""
        if len(risk_scores) == 0:
            risk_scores = np.array([50.0])

        fp_rate = self.fp / max(self.fp + self.tn, 1)
        detection_rate = self.tp / max(self.tp + self.fn, 1)

        return np.array([
            np.mean(risk_scores),
            np.std(risk_scores),
            self.lower,
            self.upper,
            fp_rate,
            detection_rate,
        ], dtype=np.float32)

    def apply_action(self, action: int) -> List[float]:
        """Apply action to adjust thresholds. Returns new [lower, upper]."""
        s = self.step_size

        if action == 0:    # no change
            pass
        elif action == 1:  # widen (more permissive)
            self.lower = max(0.0, self.lower - s)
            self.upper = min(100.0, self.upper + s)
        elif action == 2:  # narrow (more sensitive)
            self.lower = min(self.lower + s, self.upper - 5.0)
            self.upper = max(self.upper - s, self.lower + 5.0)
        elif action == 3:  # shift up
            self.lower = min(self.lower + s, 95.0)
            self.upper = min(self.upper + s, 100.0)
        elif action == 4:  # shift down
            self.lower = max(self.lower - s, 0.0)
            self.upper = max(self.upper - s, 5.0)

        return [self.lower, self.upper]

    def compute_reward(self, feedback: str) -> float:
        """Compute reward from analyst feedback."""
        cfg = self.cfg
        if feedback == "Positive":       # true positive
            self.tp += 1
            return cfg.reward_true_positive
        elif feedback == "Negative":     # false positive
            self.fp += 1
            return cfg.reward_false_positive
        elif feedback == "TrueNegative": # correctly not flagged
            self.tn += 1
            return cfg.reward_true_negative
        elif feedback == "FalseNegative": # missed anomaly
            self.fn += 1
            return cfg.reward_false_negative
        else:  # "Nil" or unknown
            return 0.0

    def get_threshold(self) -> List[float]:
        return [self.lower, self.upper]


# ──────────────────────────────────────────────────────────────────────
# DQN Agent
# ──────────────────────────────────────────────────────────────────────

class DQNAgent:
    """
    Double DQN agent for threshold optimization.

    If PyTorch is not available, falls back to rule-based heuristics.
    """

    def __init__(self, pretrained_path: Optional[str] = None):
        self.cfg = get_config().rl
        self.epsilon = self.cfg.epsilon_start
        self.use_nn = HAS_TORCH

        if self.use_nn:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.policy_net = DQNetwork(
                self.cfg.state_dim, self.cfg.action_dim, self.cfg.hidden_dims
            ).to(self.device)
            self.target_net = DQNetwork(
                self.cfg.state_dim, self.cfg.action_dim, self.cfg.hidden_dims
            ).to(self.device)
            self.target_net.load_state_dict(self.policy_net.state_dict())
            self.target_net.eval()

            self.optimizer = optim.Adam(
                self.policy_net.parameters(), lr=self.cfg.learning_rate
            )
            self.replay_buffer = ReplayBuffer(self.cfg.buffer_size)
            self.steps = 0

            if pretrained_path:
                self.load(pretrained_path)

            logger.info("DQN agent initialized (device=%s)", self.device)
        else:
            logger.info("Rule-based fallback agent initialized")

    def select_action(self, state: np.ndarray) -> int:
        """Epsilon-greedy action selection."""
        if not self.use_nn:
            return self._rule_based_action(state)

        if random.random() < self.epsilon:
            return random.randint(0, self.cfg.action_dim - 1)

        with torch.no_grad():
            state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_t)
            return int(q_values.argmax(dim=1).item())

    def _rule_based_action(self, state: np.ndarray) -> int:
        """Simple heuristic fallback when PyTorch is unavailable."""
        # state: [mean_risk, std_risk, lower_th, upper_th, fp_rate, detection_rate]
        fp_rate = state[4]
        detection_rate = state[5]

        if fp_rate > 0.3:
            return 1  # widen thresholds to reduce FP
        elif detection_rate < 0.5:
            return 2  # narrow thresholds to catch more
        elif fp_rate > 0.15:
            return 3  # shift up
        else:
            return 0  # no change

    def store_experience(self, exp: Experience) -> None:
        """Store experience in replay buffer."""
        if self.use_nn:
            self.replay_buffer.push(exp)

    def train_step(self) -> Optional[float]:
        """Perform one training step. Returns loss or None."""
        if not self.use_nn:
            return None
        if len(self.replay_buffer) < self.cfg.min_buffer_size:
            return None

        batch = self.replay_buffer.sample(self.cfg.batch_size)

        states = torch.FloatTensor(np.array([e.state for e in batch])).to(self.device)
        actions = torch.LongTensor([e.action for e in batch]).unsqueeze(1).to(self.device)
        rewards = torch.FloatTensor([e.reward for e in batch]).unsqueeze(1).to(self.device)
        next_states = torch.FloatTensor(np.array([e.next_state for e in batch])).to(self.device)
        dones = torch.FloatTensor([float(e.done) for e in batch]).unsqueeze(1).to(self.device)

        # Double DQN: use policy net to select action, target net to evaluate
        current_q = self.policy_net(states).gather(1, actions)

        with torch.no_grad():
            next_actions = self.policy_net(next_states).argmax(dim=1, keepdim=True)
            next_q = self.target_net(next_states).gather(1, next_actions)
            target_q = rewards + self.cfg.gamma * next_q * (1 - dones)

        loss = nn.functional.smooth_l1_loss(current_q, target_q)

        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping for stability
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        # Decay epsilon
        self.epsilon = max(self.cfg.epsilon_end,
                          self.epsilon * self.cfg.epsilon_decay)

        # Periodic target network update
        self.steps += 1
        if self.steps % self.cfg.target_update_freq == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

        return float(loss.item())

    def save(self, filepath: str) -> None:
        """Save agent state."""
        if not self.use_nn:
            logger.info("Rule-based agent has no state to save")
            return
        torch.save({
            "policy_net": self.policy_net.state_dict(),
            "target_net": self.target_net.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "epsilon": self.epsilon,
            "steps": self.steps,
        }, filepath)
        logger.info("DQN agent saved to %s", filepath)

    def load(self, filepath: str) -> None:
        """Load agent state."""
        if not self.use_nn:
            return
        try:
            checkpoint = torch.load(filepath, map_location=self.device)
            self.policy_net.load_state_dict(checkpoint["policy_net"])
            self.target_net.load_state_dict(checkpoint["target_net"])
            self.optimizer.load_state_dict(checkpoint["optimizer"])
            self.epsilon = checkpoint.get("epsilon", self.cfg.epsilon_end)
            self.steps = checkpoint.get("steps", 0)
            logger.info("DQN agent loaded from %s (epsilon=%.3f, steps=%d)",
                       filepath, self.epsilon, self.steps)
        except Exception as e:
            logger.error("Failed to load DQN agent: %s", e)


# ──────────────────────────────────────────────────────────────────────
# RL-based threshold optimizer (integrates with detection pipeline)
# ──────────────────────────────────────────────────────────────────────

class RLThresholdOptimizer:
    """
    Manages per-user threshold environments and a shared DQN agent.

    Usage:
        optimizer = RLThresholdOptimizer(threshold_dict)
        new_thresholds = optimizer.optimize(user, risk_scores, feedback)
    """

    def __init__(
        self,
        threshold_dict: Dict[str, List[float]],
        agent_path: Optional[str] = None,
    ):
        self.cfg = get_config()
        self.agent = DQNAgent(pretrained_path=agent_path)
        self.envs: Dict[str, ThresholdEnv] = {}
        self.threshold_dict = threshold_dict

        # Initialize environments for existing users
        default_th = self.cfg.detection.default_threshold
        for user, th in threshold_dict.items():
            self.envs[user] = ThresholdEnv(th)

        self._default_threshold = default_th
        logger.info("RL optimizer initialized with %d user environments", len(self.envs))

    def _get_env(self, user: str) -> ThresholdEnv:
        """Get or create environment for a user."""
        if user not in self.envs:
            th = self.threshold_dict.get(user, list(self._default_threshold))
            self.envs[user] = ThresholdEnv(th)
        return self.envs[user]

    def optimize(
        self,
        user: str,
        risk_scores: np.ndarray,
        feedback: str,
    ) -> List[float]:
        """
        Run one RL step for a user: observe state, select action, get reward, update.

        Args:
            user: Username
            risk_scores: Array of risk scores from current detection
            feedback: "Positive", "Negative", "Nil", "TrueNegative", "FalseNegative"

        Returns:
            Updated [lower_threshold, upper_threshold]
        """
        env = self._get_env(user)

        # Current state
        state = env.get_state(risk_scores)

        # Select action
        action = self.agent.select_action(state)

        # Apply action
        new_threshold = env.apply_action(action)

        # Compute reward
        reward = env.compute_reward(feedback)

        # Next state
        next_state = env.get_state(risk_scores)

        # Store experience and train
        done = False  # continuous learning, never "done"
        exp = Experience(state, action, reward, next_state, done)
        self.agent.store_experience(exp)
        loss = self.agent.train_step()

        # Update threshold dict
        self.threshold_dict[user] = new_threshold

        if loss is not None:
            logger.debug("RL step: user=%s action=%d reward=%.1f loss=%.4f th=%s",
                        user, action, reward, loss, new_threshold)

        return new_threshold

    def get_all_thresholds(self) -> Dict[str, List[float]]:
        """Return current threshold dict for all users."""
        for user, env in self.envs.items():
            self.threshold_dict[user] = env.get_threshold()
        return self.threshold_dict

    def save_agent(self, filepath: str) -> None:
        """Save the DQN agent."""
        self.agent.save(filepath)

    def load_agent(self, filepath: str) -> None:
        """Load a pretrained DQN agent."""
        self.agent.load(filepath)
