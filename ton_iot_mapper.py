import pandas as pd
import numpy as np
import datetime
import os
from pathlib import Path

def parse_ton_iot_date(ts):
    try:
        # Check if it's already a datetime or timestamp
        if pd.isna(ts):
            return datetime.datetime.now().isoformat()
        
        # Try converting unix timestamp
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace('.', '', 1).isdigit()):
            return datetime.datetime.fromtimestamp(float(ts)).isoformat()
            
        return pd.to_datetime(ts).isoformat()
    except:
        return datetime.datetime.now().isoformat()

def get_severity(duration):
    try:
        d = float(duration)
        if d < 1.0: return "Low"
        elif d <= 10.0: return "Medium"
        else: return "High"
    except:
        return "Low"

def get_subnet(ip_addr):
    try:
        parts = str(ip_addr).split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3])
    except:
        pass
    return "unknown"

def infer_hostname_from_port(port):
    """Synthetically derive hostname from port, mimicking UNSW-NB15 preprocessing"""
    try:
        p = int(port)
        if p == 80 or p == 443: return "web_server"
        if p == 53: return "dns_server"
        if p == 21 or p == 22: return "admin_server"
        if p == 1883: return "mqtt_broker"
        if p == 502: return "modbus_plc"
        if p == 3306: return "db_server"
    except:
        pass
    return f"host_port_{port}"

def map_ton_iot(input_csv, output_parquet):
    print(f"Mapping TON_IoT data from {input_csv}...")
    
    # Read CSV
    df = pd.read_csv(input_csv, low_memory=False)
    print(f"Loaded {len(df)} records. Mapping to 11-field schema...")
    
    # Initialize output dataframe
    mapped_df = pd.DataFrame()
    
    # Map required fields
    # 1. EndDate
    ts_col = 'ts' if 'ts' in df.columns else 'date' if 'date' in df.columns else None
    if ts_col:
        mapped_df['EndDate'] = df[ts_col].apply(parse_ton_iot_date)
    else:
        mapped_df['EndDate'] = datetime.datetime.now().isoformat()
        
    # 2. SourceAddress
    mapped_df['SourceAddress'] = df['src_ip'] if 'src_ip' in df.columns else "0.0.0.0"
    
    # 3. DestinationAddress
    mapped_df['DestinationAddress'] = df['dst_ip'] if 'dst_ip' in df.columns else "0.0.0.0"
    
    # 4. DeviceAddress (proto:port)
    proto = df['proto'] if 'proto' in df.columns else "tcp"
    src_port = df['src_port'] if 'src_port' in df.columns else "0"
    mapped_df['DeviceAddress'] = proto.astype(str) + ":" + src_port.astype(str)
    
    # 5. AttackSeverity
    dur_col = 'duration' if 'duration' in df.columns else None
    if dur_col:
        mapped_df['AttackSeverity'] = df[dur_col].apply(get_severity)
    else:
        mapped_df['AttackSeverity'] = "Low"
        
    # 6. MalwareIntelAttackType
    if 'type' in df.columns:
        mapped_df['MalwareIntelAttackType'] = df['type'].fillna("benign")
    else:
        mapped_df['MalwareIntelAttackType'] = "benign"
        
    # 7. SourceUserName (gateway_<subnet>)
    subnets = mapped_df['SourceAddress'].apply(get_subnet)
    mapped_df['SourceUserName'] = "gateway_" + subnets
    
    # 8. DestinationUserName (derived from dst_port)
    dst_port = df['dst_port'] if 'dst_port' in df.columns else "0"
    mapped_df['DestinationUserName'] = dst_port.apply(infer_hostname_from_port)
    
    # 9. FileName (Not available in this network dataset)
    mapped_df['FileName'] = "N/A"
    
    # 10. FilePath (Not available)
    mapped_df['FilePath'] = "N/A"
    
    # 11. Category (0/1 to descriptive)
    if 'label' in df.columns:
        mapped_df['Category'] = df['label'].apply(lambda x: "Attack" if str(x) == "1" else "Normal")
    else:
        mapped_df['Category'] = "Unknown"
        
    # Check if we have the 11 fields exactly
    expected_cols = [
        "SourceAddress", "DestinationAddress", "DeviceAddress", "EndDate", "AttackSeverity",
        "MalwareIntelAttackType", "SourceUserName", "DestinationUserName", "FileName", 
        "FilePath", "Category"
    ]
    
    # Add any missing expected columns just in case
    for col in expected_cols:
        if col not in mapped_df.columns:
            mapped_df[col] = "N/A"
            
    mapped_df = mapped_df[expected_cols]
    
    # Save to parquet
    output_dir = Path(output_parquet).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    mapped_df.to_parquet(output_parquet)
    print(f"Successfully mapped and saved {len(mapped_df)} records to {output_parquet}")
    
    return mapped_df

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Map TON_IoT to MITRE-CORE schema")
    parser.add_argument("--input", type=str, default=r"E:\Private\MITRE-CORE 2\MITRE-CORE\datasets\TON_IoT\train_test_network.csv")
    parser.add_argument("--output", type=str, default=r"E:\Private\MITRE-CORE 2\MITRE-CORE\datasets\TON_IoT\mitre_format.parquet")
    args = parser.parse_args()
    
    map_ton_iot(args.input, args.output)
