"""
Alert Tokenization Schema for Transformer Processing
====================================================

Defines normalized alert representations for transformer input.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertToken(BaseModel):
    """
    Normalized alert representation for transformer.
    
    This is the core data structure that represents a single security alert
    in a format suitable for transformer processing.
    """
    
    # Identifiers
    alert_id: str = Field(..., description="Unique alert identifier")
    alert_type: str = Field(..., description="Alert type (e.g., 'suricata_alert', 'windows_event')")
    
    # MITRE ATT&CK
    tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic")
    technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID (e.g., 'T1001')")
    
    # Entities (hashed to vocab indices)
    src_ip_hash: int = Field(..., description="Hashed source IP address")
    dst_ip_hash: int = Field(..., description="Hashed destination IP address")
    hostname_hash: int = Field(..., description="Hashed hostname")
    username_hash: int = Field(..., description="Hashed username")
    
    # Temporal
    timestamp: datetime = Field(..., description="Alert timestamp")
    time_bucket: int = Field(..., ge=0, le=287, description="5-minute bin (0-287 for 24h)")
    
    # Severity
    severity_score: float = Field(..., ge=0.0, le=1.0, description="Normalized severity (0-1)")
    
    # Free-form text (optional, for future BERT integration)
    description: Optional[str] = Field(None, description="Alert description text")
    
    # Raw values (for debugging/reference)
    src_ip_raw: Optional[str] = Field(None, description="Original source IP (for reference)")
    dst_ip_raw: Optional[str] = Field(None, description="Original destination IP (for reference)")
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EntityVocab(BaseModel):
    """
    Entity vocabulary mapping for a batch.
    
    Maps hash values back to original entity strings for interpretability.
    """
    
    ip_vocab: Dict[int, str] = Field(default_factory=dict, description="IP hash -> IP string")
    hostname_vocab: Dict[int, str] = Field(default_factory=dict, description="Hostname hash -> string")
    username_vocab: Dict[int, str] = Field(default_factory=dict, description="Username hash -> string")
    
    def get_entity(self, entity_type: str, hash_val: int) -> Optional[str]:
        """Get original entity string from hash."""
        vocab_map = {
            'ip': self.ip_vocab,
            'hostname': self.hostname_vocab,
            'username': self.username_vocab
        }
        return vocab_map.get(entity_type, {}).get(hash_val)


class AlertBatch(BaseModel):
    """
    Batch of alerts for transformer processing.
    
    Contains multiple alerts with shared metadata and entity vocabulary.
    """
    
    batch_id: str = Field(..., description="Unique batch identifier")
    window_start: datetime = Field(..., description="Batch window start time")
    window_end: datetime = Field(..., description="Batch window end time")
    alerts: List[AlertToken] = Field(..., description="List of alerts in batch")
    
    # Entity mapping for this batch
    entity_vocab: EntityVocab = Field(default_factory=EntityVocab, description="Entity vocabulary")
    
    # Ground truth (for training)
    campaign_labels: Optional[List[int]] = Field(None, description="Campaign IDs for each alert (training only)")
    
    # Metadata
    source_dataset: Optional[str] = Field(None, description="Source dataset name")
    total_entities: int = Field(0, description="Total unique entities in batch")
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def get_alert_by_id(self, alert_id: str) -> Optional[AlertToken]:
        """Retrieve alert by ID."""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                return alert
        return None
    
    def get_entities_by_type(self, entity_type: str) -> set:
        """Get all unique entity hashes of a specific type."""
        if entity_type == 'ip':
            return set(a.src_ip_hash for a in self.alerts) | set(a.dst_ip_hash for a in self.alerts)
        elif entity_type == 'hostname':
            return set(a.hostname_hash for a in self.alerts)
        elif entity_type == 'username':
            return set(a.username_hash for a in self.alerts)
        return set()


class BatchMetadata(BaseModel):
    """
    Metadata for a processed batch.
    
    Tracks processing statistics and quality metrics.
    """
    
    num_alerts: int = Field(..., description="Number of alerts in batch")
    num_entities: int = Field(..., description="Number of unique entities")
    time_span_seconds: float = Field(..., description="Time span of batch in seconds")
    avg_severity: float = Field(..., ge=0.0, le=1.0, description="Average severity score")
    
    # Quality metrics
    missing_tactics_pct: float = Field(0.0, ge=0.0, le=100.0, description="Percentage of alerts missing tactic")
    missing_techniques_pct: float = Field(0.0, ge=0.0, le=100.0, description="Percentage of alerts missing technique")
    
    # Processing info
    processed_at: datetime = Field(default_factory=datetime.now, description="Processing timestamp")
    preprocessor_version: str = Field("1.0.0", description="Preprocessor version")
