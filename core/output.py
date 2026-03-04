import pandas as pd 
from core import postprocessing
import json

#  Data dictionaries


types = {
"Connection to Malicious URL for malware_download": "INITIAL ACCESS",
    "Event Triggered Execution": "EXECUTION",
    "Persistence - Registry Key Manipulation": "PERSISTENCE",
    "Privilege Escalation - Exploiting Vulnerability": "PRIVILEGE ESCALATION",
    "Defense Evasion - Signature-based Evasion": "DEFENSE EVASION",
    "Credential Access - Password Guessing" : "CREDENTIAL ACCESS",
    "Discovery - Network Service Scanning": "DISCOVERY",
    "Lateral Movement - Remote Desktop Protocol (RDP) Exploitation": "LATERAL MOVEMENT",
    "Collection - Data Exfiltration via Email": "COLLECTION",
    "Command and Control - Communication over Tor Network": "COMMAND AND CONTROL",
    "Exfiltration - File Transfer to External Server": "EXFILTRATION",
    "Impact - Denial-of-Service (DoS) Attack": "IMPACT"
}


Attack_stages = {

    "Initial": [
        ['INITIAL ACCESS', 'EXECUTION'],
        ['INITIAL ACCESS', 'EXECUTION', 'PERSISTENCE'],
        ['INITIAL ACCESS', 'CREDENTIAL ACCESS', 'DISCOVERY']
        ],
    "Partial": [
        ['PERSISTENCE', 'PRIVILEGE ESCALATION', 'CREDENTIAL ACCESS', 'DISCOVERY']
    ],

    "Complete": [
        ['INITIAL ACCESS', 'EXECUTION', 'PERSISTENCE', 'PRIVILEGE ESCALATION', 'DEFENSE EVASION', 'CREDENTIAL ACCESS', 'DISCOVERY', 'LATERAL MOVEMENT', 'COLLECTION', 'COMMAND AND CONTROL', 'IMPACT'],
        ['INITIAL ACCESS', 'EXECUTION', 'DEFENSE EVASION', 'EXFILTRATION', 'IMPACT'],
        ['PERSISTENCE', 'CREDENTIAL ACCESS', 'COLLECTION', 'EXFILTRATION']
    ]

    
}




def classify_attack_stage(tactics):
    """Classify the attack stage based on observed tactics.
    
    Compares the set of observed tactics against known attack chain patterns
    to determine if the cluster represents a Complete, Partial, or Initial attack.
    """
    tactics_set = set(tactics)
    
    # Check Complete patterns first (most severe)
    for pattern in Attack_stages["Complete"]:
        if set(pattern).issubset(tactics_set):
            return "Potential Hit"
    
    # Check Partial patterns
    for pattern in Attack_stages["Partial"]:
        if set(pattern).issubset(tactics_set):
            return "Partial"
    
    # Check Initial patterns
    for pattern in Attack_stages["Initial"]:
        if set(pattern).issubset(tactics_set):
            return "Initial"
    
    return "Other"


def generate_output(input_path="Data/Cleaned/Test_test_dataset.csv", output_path="output.json"):
    """Generate JSON output from correlated cluster data."""
    data = pd.read_csv(input_path)
    data['cluster'] = data['pred_cluster']

    addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
    usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]

    correlated_factors = postprocessing.get_feature_chains(data, usernames, addresses)

    compiled_output = []
    customerName = list(set(data['CustomerName']))[0]

    clusters = data.groupby('cluster')

    for c_no, cluster in clusters:
        start_date = min(cluster['EndDate'])
        end_date = max(cluster['EndDate'])
        subattack_types = list(set(cluster['MalwareIntelAttackType']))
        tactics = list(set([types.get(description, "UNKNOWN") for description in subattack_types]))
        device_addresses = list(set(cluster['DeviceAddress']))
        print("cluster" , c_no)

        stage = classify_attack_stage(tactics)

        json_obj = {
            "start_date": start_date,
            "end_date": end_date,
            "correlationFactor": correlated_factors.get(c_no, []),
            "CustomerName": customerName,
            "SubAttackType": subattack_types,
            "DeviceAddress": device_addresses,
            "Tactic": tactics,
            "Scenario_type": stage
        }
        compiled_output.append(json_obj)

    print(compiled_output)

    with open(output_path, 'w') as file:
        json.dump(compiled_output, file, indent=4)
    
    return compiled_output


if __name__ == "__main__":
    generate_output()
