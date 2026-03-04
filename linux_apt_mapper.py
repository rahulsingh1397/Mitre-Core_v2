import pandas as pd
import numpy as np
import json
import os
from pathlib import Path
import datetime

# Create a deterministic mock dataset based on Linux APT sequences
# In a real environment, this would parse real auditd/sysmon logs
def map_linux_apt(output_path):
    print("Generating simulated Linux APT sequences based on tactic_map.json...")
    
    # We create deterministic sequences representing different multi-stage APTs
    # Each APT campaign gets a unique combination of host/user to allow Union-Find to group them
    
    records = []
    
    # Campaign 1: Web Exploit -> PrivEsc -> Exfiltration
    base_time = datetime.datetime(2026, 1, 1, 10, 0, 0)
    campaign1 = [
        {"MalwareIntelAttackType": "exploit", "AttackSeverity": "Medium", "DeviceAddress": "10.0.0.5", "SourceAddress": "192.168.1.100", "SourceUserName": "www-data", "SourceHostName": "webserver1", "DestinationHostName": "webserver1"},
        {"MalwareIntelAttackType": "command", "AttackSeverity": "High", "DeviceAddress": "10.0.0.5", "SourceAddress": "10.0.0.5", "SourceUserName": "www-data", "SourceHostName": "webserver1", "DestinationHostName": "webserver1"},
        {"MalwareIntelAttackType": "privilege_escalation", "AttackSeverity": "Critical", "DeviceAddress": "10.0.0.5", "SourceAddress": "10.0.0.5", "SourceUserName": "root", "SourceHostName": "webserver1", "DestinationHostName": "webserver1"},
        {"MalwareIntelAttackType": "archive", "AttackSeverity": "Medium", "DeviceAddress": "10.0.0.5", "SourceAddress": "10.0.0.5", "SourceUserName": "root", "SourceHostName": "webserver1", "DestinationHostName": "webserver1"},
        {"MalwareIntelAttackType": "c2_exfil", "AttackSeverity": "Critical", "DeviceAddress": "10.0.0.5", "SourceAddress": "10.0.0.5", "SourceUserName": "root", "SourceHostName": "webserver1", "DestinationAddress": "198.51.100.5"}
    ]
    for i, r in enumerate(campaign1):
        r['EndDate'] = (base_time + datetime.timedelta(minutes=i*5)).isoformat()
        r['campaign'] = 'APT_Campaign_1'
        records.append(r)
        
    # Campaign 2: Phishing -> Lateral Movement -> Credential Dumping
    base_time = datetime.datetime(2026, 1, 1, 14, 0, 0)
    campaign2 = [
        {"MalwareIntelAttackType": "phishing", "AttackSeverity": "Medium", "DeviceAddress": "10.0.0.12", "SourceAddress": "203.0.113.10", "SourceUserName": "alice", "SourceHostName": "workstation-1", "DestinationHostName": "workstation-1"},
        {"MalwareIntelAttackType": "execution", "AttackSeverity": "High", "DeviceAddress": "10.0.0.12", "SourceAddress": "10.0.0.12", "SourceUserName": "alice", "SourceHostName": "workstation-1", "DestinationHostName": "workstation-1"},
        {"MalwareIntelAttackType": "smb_lateral", "AttackSeverity": "High", "DeviceAddress": "10.0.0.12", "SourceAddress": "10.0.0.12", "SourceUserName": "alice", "SourceHostName": "workstation-1", "DestinationAddress": "10.0.0.50", "DestinationHostName": "fileserver"},
        {"MalwareIntelAttackType": "dump", "AttackSeverity": "Critical", "DeviceAddress": "10.0.0.50", "SourceAddress": "10.0.0.12", "SourceUserName": "alice", "SourceHostName": "fileserver", "DestinationHostName": "fileserver"}
    ]
    for i, r in enumerate(campaign2):
        r['EndDate'] = (base_time + datetime.timedelta(minutes=i*15)).isoformat()
        r['campaign'] = 'APT_Campaign_2'
        records.append(r)
        
    # Add multiple noisy "normal" or single isolated alerts
    base_time = datetime.datetime(2026, 1, 1, 12, 0, 0)
    for i in range(50):
        records.append({
            "MalwareIntelAttackType": "scan",
            "AttackSeverity": "Low",
            "DeviceAddress": f"10.0.0.{np.random.randint(1, 200)}",
            "SourceAddress": f"192.168.2.{np.random.randint(1, 255)}",
            "SourceUserName": "unknown",
            "SourceHostName": f"host-{np.random.randint(1, 100)}",
            "DestinationHostName": "unknown",
            "EndDate": (base_time + datetime.timedelta(minutes=np.random.randint(1, 1000))).isoformat(),
            "campaign": "Noise"
        })
        
    df = pd.DataFrame(records)
    
    # Fill required missing fields with N/A
    expected_cols = [
        "SourceAddress", "DestinationAddress", "DeviceAddress", "EndDate", "AttackSeverity",
        "MalwareIntelAttackType", "SourceUserName", "DestinationUserName", "FileName", 
        "FilePath", "Category", "SourceHostName", "DeviceHostName", "DestinationHostName"
    ]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = "N/A"
            
    df['AlertId'] = [f"APT_{i}" for i in range(len(df))]
    
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path)
    
    print(f"Generated Linux APT mock dataset with {len(df)} records at {output_path}")
    return df

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=str, default=r"E:\Private\MITRE-CORE 2\MITRE-CORE\datasets\Linux_APT\mitre_format.parquet")
    args = parser.parse_args()
    map_linux_apt(args.output)
