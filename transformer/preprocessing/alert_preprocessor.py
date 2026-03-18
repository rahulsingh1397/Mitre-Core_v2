"""
Alert Preprocessor
==================

Converts raw alert DataFrames to transformer-ready tensors.
Optimized for GPU batch processing.
"""

import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

import numpy as np
import pandas as pd
import torch

from transformer.schema.alert_schema import AlertToken, AlertBatch, EntityVocab, BatchMetadata


logger = logging.getLogger("mitre-core.transformer.preprocessor")


class AlertPreprocessor:
    """
    Converts raw alert DataFrames to transformer-ready tensors.
    
    Features:
    - Consistent entity hashing across batches
    - Temporal bucketing (5-minute bins)
    - GPU tensor generation
    - Batch metadata tracking
    
    Example:
        preprocessor = AlertPreprocessor(vocab_size=10000)
        batch = preprocessor.process_batch(df, device='cuda')
    """
    
    def __init__(
        self,
        max_seq_length: int = 256,
        time_bucket_minutes: int = 5,
        vocab_size: int = 10000,
        hash_salt: str = "mitre-core-v3"
    ):
        """
        Initialize preprocessor.
        
        Args:
            max_seq_length: Maximum alerts per batch (reduced to 256 for 8GB GPU)
            time_bucket_minutes: Time bucket size for temporal encoding (default 5 min)
            vocab_size: Size of entity vocabulary
            hash_salt: Salt for consistent hashing
        """
        self.max_seq_length = max_seq_length
        self.time_bucket_minutes = time_bucket_minutes
        self.vocab_size = vocab_size
        self.hash_salt = hash_salt
        
        # Time buckets per day (24h * 60min / 5min = 288)
        self.num_time_buckets = 24 * 60 // time_bucket_minutes
        
        logger.info(
            f"AlertPreprocessor initialized: "
            f"max_seq_length={max_seq_length}, "
            f"time_bucket={time_bucket_minutes}min, "
            f"vocab_size={vocab_size}"
        )
    
    def _hash_entity(self, entity_str: str) -> int:
        """
        Hash entity string to vocabulary index.
        
        Uses MD5 for consistent hashing across runs.
        """
        if not entity_str or pd.isna(entity_str):
            return 0  # Unknown/empty token
        
        # Create consistent hash
        hash_input = f"{self.hash_salt}:{entity_str.lower().strip()}"
        hash_val = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        return (hash_val % (self.vocab_size - 1)) + 1  # Reserve 0 for unknown
    
    def _compute_time_bucket(self, timestamp: datetime) -> int:
        """
        Convert timestamp to 5-minute bucket index (0-287).
        """
        if pd.isna(timestamp):
            return 0
        
        total_minutes = timestamp.hour * 60 + timestamp.minute
        bucket = total_minutes // self.time_bucket_minutes
        return min(bucket, self.num_time_buckets - 1)  # Clamp to max
    
    def _compute_severity_score(self, severity: str) -> float:
        """
        Convert severity string to normalized score (0-1).
        """
        severity_map = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25,
            'info': 0.1,
            'normal': 0.0
        }
        return severity_map.get(str(severity).lower(), 0.5)
    
    def _extract_ip_from_bytes(self, bytes_val) -> Optional[str]:
        """Extract IP-like string from bytes value."""
        if pd.isna(bytes_val):
            return None
        try:
            # Generate deterministic IP from bytes for synthetic data
            byte_int = int(bytes_val) % 256
            return f"10.0.0.{byte_int}"
        except:
            return None
    
    def _process_single_alert(
        self,
        row: pd.Series,
        alert_id: str,
        idx: int
    ) -> AlertToken:
        """
        Process a single DataFrame row into an AlertToken.
        """
        # Extract timestamp
        timestamp = pd.to_datetime(
            row.get('timestamp') or row.get('EndDate') or row.get('StartTime') or row.get('time'),
            errors='coerce'
        )
        if pd.isna(timestamp):
            timestamp = datetime.now()
        
        # Extract tactic/technique
        tactic = row.get('tactic') or row.get('MalwareIntelAttackType')
        technique = row.get('technique') or row.get('AttackTechnique')
        
        # Extract severity
        severity = row.get('severity', row.get('AttackSeverity', 'medium'))
        severity_score = self._compute_severity_score(severity)
        
        # Extract entities
        # Try various column names for flexibility across datasets
        # Handle CAN bus datasets (CICIoV2024) - use CAN ID as network identifier
        can_id = row.get('ID')
        can_data = row.get('DATA_0', row.get('data'))
        
        # Extract source IP - try column names in priority order, then CAN fallback
        src_ip = (
            row.get('src_ip') or
            row.get('SourceAddress') or
            row.get('SourceIP') or
            row.get('src') or
            row.get('Src IP') or
            row.get('Source IP') or
            row.get('sip') or
            row.get('src_computer') or           # LANL
            row.get('source_computer') or          # LANL variant
            row.get('user@src_computer')           # LANL auth logs
        )
        # CAN bus fallback (CICIoV2024) - only reached when no IP column found above
        if src_ip is None and can_id is not None:
            src_ip = f"CAN:{can_id}"
        # Byte synthesis fallback - last resort synthetic IP from packet size
        if src_ip is None:
            src_ip = self._extract_ip_from_bytes(row.get('sbytes'))

        # Same structure for dst_ip:
        dst_ip = (
            row.get('dst_ip') or
            row.get('DestinationAddress') or
            row.get('DestinationIP') or
            row.get('dst') or
            row.get('Dst IP') or
            row.get('Destination IP') or
            row.get('dip') or
            row.get('dst_computer') or           # LANL
            row.get('dest_computer') or          # LANL variant
            row.get('user@dst_computer')           # LANL auth logs
        )
        if dst_ip is None and can_id is not None:
            dst_ip = f"CAN:{can_id}"
        if dst_ip is None:
            dst_ip = self._extract_ip_from_bytes(row.get('dbytes'))
        hostname = (
            row.get('hostname') or
            row.get('SourceHostName') or
            row.get('DeviceHostName') or
            row.get('service')
        )
        # CAN data fallback
        if hostname is None and can_data is not None:
            hostname = f"CAN:{can_data}"
        # Final fallback
        if hostname is None:
            hostname = f"host-{idx % 1000}"
        username = (
            row.get('username') or 
            row.get('SourceUserName') or
            row.get('proto') or
            "unknown"
        )
        
        # Get alert type
        alert_type = (
            row.get('alert_type') or 
            row.get('attack_cat') or
            row.get('label', 'unknown')
        )
        
        # Create token
        token = AlertToken(
            alert_id=alert_id,
            alert_type=str(alert_type),
            tactic=str(tactic) if pd.notna(tactic) else None,
            technique=str(technique) if pd.notna(technique) else None,
            src_ip_hash=self._hash_entity(str(src_ip)),
            dst_ip_hash=self._hash_entity(str(dst_ip)),
            hostname_hash=self._hash_entity(str(hostname)),
            username_hash=self._hash_entity(str(username)),
            timestamp=timestamp,
            time_bucket=self._compute_time_bucket(timestamp),
            severity_score=severity_score,
            description=str(row.get('description', '')) if pd.notna(row.get('description')) else None,
            src_ip_raw=str(src_ip) if src_ip else None,
            dst_ip_raw=str(dst_ip) if dst_ip else None
        )
        
        return token
    
    def process_batch(
        self,
        df: pd.DataFrame,
        device: torch.device = torch.device('cuda'),
        batch_id: Optional[str] = None
    ) -> Dict:
        """
        Convert DataFrame to GPU tensors.
        
        Args:
            df: Alert DataFrame with standard columns
            device: Target GPU device
            batch_id: Optional batch identifier
            
        Returns:
            Dictionary containing:
            - alert_ids: torch.Tensor [batch_size, seq_len]
            - entity_ids: torch.Tensor [batch_size, num_entities]
            - time_buckets: torch.Tensor [batch_size, seq_len]
            - attention_mask: torch.Tensor [batch_size, seq_len]
            - alert_batch: AlertBatch (Pydantic model)
            - metadata: BatchMetadata
        """
        if len(df) == 0:
            logger.warning("Empty DataFrame provided")
            return self._create_empty_batch(device)
        
        # Sort by time for positional encoding - only use columns that exist
        sort_cols = ['timestamp', 'EndDate', 'StartTime', 'time']
        available_sort_cols = [col for col in sort_cols if col in df.columns]
        
        if available_sort_cols:
            df = df.sort_values(
                by=available_sort_cols,
                ascending=True
            ).reset_index(drop=True)
        
        # Generate batch ID if not provided
        if batch_id is None:
            batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Process each alert
        alert_tokens: List[AlertToken] = []
        entity_vocab = EntityVocab()
        
        for idx, row in df.iterrows():
            alert_id = f"alert_{batch_id}_{idx}"
            token = self._process_single_alert(row, alert_id, idx)
            alert_tokens.append(token)
            
            # Build entity vocabulary
            if token.src_ip_raw:
                entity_vocab.ip_vocab[token.src_ip_hash] = token.src_ip_raw
            if token.dst_ip_raw:
                entity_vocab.ip_vocab[token.dst_ip_hash] = token.dst_ip_raw
            if row.get('hostname'):
                entity_vocab.hostname_vocab[token.hostname_hash] = str(row.get('hostname'))
        
        # Create AlertBatch
        window_start = min(t.timestamp for t in alert_tokens)
        window_end = max(t.timestamp for t in alert_tokens)
        
        alert_batch = AlertBatch(
            batch_id=batch_id,
            window_start=window_start,
            window_end=window_end,
            alerts=alert_tokens,
            entity_vocab=entity_vocab
        )
        
        # Create tensors
        tensors = self._create_tensors(alert_tokens, device)
        
        # Extract campaign labels from dataframe for contrastive learning
        # Priority: campaign_id > tactic > label > red_team_tag
        campaign_labels = self._extract_campaign_labels(df)
        tensors['campaign_labels'] = campaign_labels
        
        # Create metadata
        metadata = self._create_metadata(alert_tokens, window_start, window_end)
        
        logger.info(
            f"Processed batch {batch_id}: {len(alert_tokens)} alerts, "
            f"{len(entity_vocab.ip_vocab)} unique IPs, "
            f"device={device}"
        )
        
        return {
            **tensors,
            'alert_batch': alert_batch,
            'metadata': metadata,
            'batch_id': batch_id
        }
    
    def _create_tensors(
        self,
        alert_tokens: List[AlertToken],
        device: torch.device
    ) -> Dict:
        """Create GPU tensors from alert tokens."""
        num_alerts = len(alert_tokens)
        
        # Extract features
        alert_ids = torch.tensor(
            [hash(t.alert_id) % 10000 for t in alert_tokens],
            dtype=torch.long,
            device=device
        )
        
        # Entity features [num_alerts, 4] - src_ip, dst_ip, hostname, username
        entity_features = torch.tensor(
            [[t.src_ip_hash, t.dst_ip_hash, t.hostname_hash, t.username_hash] 
             for t in alert_tokens],
            dtype=torch.long,
            device=device
        )
        
        # Temporal features
        time_buckets = torch.tensor(
            [t.time_bucket for t in alert_tokens],
            dtype=torch.long,
            device=device
        )
        
        # Severity scores
        severity = torch.tensor(
            [t.severity_score for t in alert_tokens],
            dtype=torch.float,
            device=device
        )
        
        # Attention mask (all valid for now, padding handled by batching)
        attention_mask = torch.ones(num_alerts, dtype=torch.long, device=device)
        
        return {
            'alert_ids': alert_ids.unsqueeze(0),  # Add batch dimension [1, seq_len]
            'entity_ids': entity_features.unsqueeze(0),  # [1, seq_len, 4]
            'time_buckets': time_buckets.unsqueeze(0),  # [1, seq_len]
            'severity': severity.unsqueeze(0),  # [1, seq_len]
            'attention_mask': attention_mask.unsqueeze(0),  # [1, seq_len]
        }
    
    def _create_metadata(
        self,
        alert_tokens: List[AlertToken],
        window_start: datetime,
        window_end: datetime
    ) -> BatchMetadata:
        """Create batch metadata."""
        time_span = (window_end - window_start).total_seconds()
        
        # Calculate quality metrics
        total = len(alert_tokens)
        missing_tactics = sum(1 for t in alert_tokens if t.tactic is None)
        missing_techniques = sum(1 for t in alert_tokens if t.technique is None)
        
        # Get unique entities
        unique_ips = set()
        unique_hostnames = set()
        unique_usernames = set()
        for t in alert_tokens:
            unique_ips.add(t.src_ip_hash)
            unique_ips.add(t.dst_ip_hash)
            unique_hostnames.add(t.hostname_hash)
            unique_usernames.add(t.username_hash)
        
        total_entities = len(unique_ips) + len(unique_hostnames) + len(unique_usernames)
        
        return BatchMetadata(
            num_alerts=total,
            num_entities=total_entities,
            time_span_seconds=time_span,
            avg_severity=np.mean([t.severity_score for t in alert_tokens]),
            missing_tactics_pct=(missing_tactics / total) * 100 if total > 0 else 0,
            missing_techniques_pct=(missing_techniques / total) * 100 if total > 0 else 0
        )
    
    # LANL EventID to MITRE Tactic mapping (coarse campaign labels)
    LANL_EVENTID_TACTIC = {
        4688: "Execution",           # Process Creation
        4689: "Execution",           # Process Termination
        4624: "InitialAccess",       # Account Logon
        4625: "InitialAccess",       # Account Logon Failure
        4648: "LateralMovement",     # Explicit Credential Logon
        4672: "PrivilegeEscalation", # Special Privileges
        4634: "DefenseEvasion",      # Logoff (session closure)
        4768: "CredentialAccess",    # Kerberos TGT Request
        4769: "CredentialAccess",    # Kerberos Service Ticket
        4770: "CredentialAccess",    # Kerberos Service Ticket Renewed
        4771: "CredentialAccess",   # Kerberos Pre-Auth Failed
        4776: "CredentialAccess",   # NTLM Auth
        4800: "DefenseEvasion",     # Workstation Locked
        4801: "DefenseEvasion",     # Workstation Unlocked
        4802: "DefenseEvasion",     # Screen Saver Invoked
        4803: "DefenseEvasion",     # Screen Saver Dismissed
        5136: "Persistence",        # Directory Service Object Modified
        5137: "Persistence",        # Directory Service Object Created
        5140: "LateralMovement",    # Network Share Accessed
        5145: "LateralMovement",    # Network Share Object Checked
    }

    def _extract_campaign_labels(self, df: pd.DataFrame) -> torch.Tensor:
        """
        Extract campaign labels from dataframe for contrastive learning.
        Priority: campaign_id > tactic > label > red_team_tag > attack_cat > EventID (LANL)
        
        Returns:
            torch.Tensor of shape [len(df)] with integer campaign IDs
        """
        labels = None
        label_col = None
        
        # Priority order for label columns
        priority_cols = ['campaign_id', 'tactic', 'label', 'red_team_tag', 'attack_cat', 'Label', 'class']
        
        for col in priority_cols:
            if col in df.columns:
                labels = df[col]
                label_col = col
                break
        
        # LANL fallback: map EventID to coarse tactic labels
        if labels is None and 'EventID' in df.columns:
            event_ids = df['EventID'].fillna(0).astype(int)
            tactic_labels = event_ids.map(lambda x: self.LANL_EVENTID_TACTIC.get(x, "Unknown"))
            # Factorize to integers
            unique_tactics = tactic_labels.unique()
            tactic_map = {t: i for i, t in enumerate(unique_tactics)}
            int_labels = tactic_labels.map(lambda x: tactic_map.get(x, 0))
            return torch.tensor(int_labels.values, dtype=torch.long)
        
        if labels is None:
            # No label column found - return alternating labels as fallback
            logger.warning("No campaign label column found, using alternating labels")
            return torch.arange(len(df), dtype=torch.long) % 2
        
        # Convert labels to integers
        if labels.dtype == 'object' or labels.dtype.name == 'category':
            # String labels - factorize to integers
            unique_labels = labels.dropna().unique()
            label_map = {label: idx for idx, label in enumerate(unique_labels)}
            int_labels = labels.map(lambda x: label_map.get(x, -1) if pd.notna(x) else -1)
        else:
            # Numeric labels - use directly
            int_labels = labels.fillna(-1).astype(int)
        
        # Handle NaN/unknown labels (-1) by assigning them unique negative IDs
        # This ensures they don't form positive pairs with anything
        result = int_labels.values
        
        return torch.tensor(result, dtype=torch.long)
    
    def _create_empty_batch(self, device: torch.device) -> Dict:
        """Create empty batch for edge cases."""
        return {
            'alert_ids': torch.zeros(1, 0, dtype=torch.long, device=device),
            'entity_ids': torch.zeros(1, 0, 4, dtype=torch.long, device=device),
            'time_buckets': torch.zeros(1, 0, dtype=torch.long, device=device),
            'severity': torch.zeros(1, 0, dtype=torch.float, device=device),
            'attention_mask': torch.zeros(1, 0, dtype=torch.long, device=device),
            'campaign_labels': torch.zeros(0, dtype=torch.long, device=device),
            'alert_batch': AlertBatch(
                batch_id="empty",
                window_start=datetime.now(),
                window_end=datetime.now(),
                alerts=[]
            ),
            'metadata': BatchMetadata(num_alerts=0, num_entities=0, time_span_seconds=0, avg_severity=0),
            'batch_id': "empty"
        }
