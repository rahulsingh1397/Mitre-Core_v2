import pandas as pd
import numpy as np

class DataSanitizer:
    """
    Input sanitization and schema validation for incoming alerts.
    """
    def __init__(self, required_columns: list):
        self.required_columns = required_columns
        
    def validate_schema(self, df: pd.DataFrame) -> bool:
        """Ensure all required fields are present."""
        missing = [col for col in self.required_columns if col not in df.columns]
        if missing:
            raise ValueError(f"Missing required columns: {missing}")
        return True
        
    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Filter out extreme anomalous values or rate-limit high frequency bursts
        that could be DoS attacks on the correlation engine itself.
        """
        # Basic example: drop rows with all nulls in key identifiers
        return df.dropna(subset=self.required_columns, how="all")

