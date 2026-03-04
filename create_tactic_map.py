import json
import os
from pathlib import Path

# Note: I couldn't find an existing tactic_map.json, so I'm creating one with the 12 tactics mentioned plus the 2 new ones.
# The previous 12 are inferred based on the prompt or common ATT&CK terms.
tactic_map = {
    "Initial Access": ["initial_access", "phishing", "exploit"],
    "Execution": ["execution", "command", "script"],
    "Persistence": ["persistence", "registry", "cron"],
    "Privilege Escalation": ["privilege_escalation", "sudo", "root"],
    "Defense Evasion": ["defense_evasion", "obfuscation", "clear_logs"],
    "Credential Access": ["credential_access", "brute_force", "dump"],
    "Discovery": ["discovery", "scan", "enum"],
    "Collection": ["collection", "archive", "compress"],
    "Command and Control": ["command_and_control", "c2", "beacon"],
    "Impact": ["impact", "dos", "ransomware"],
    "Lateral Movement": ["lateral", "smb_lateral", "pass_the_hash", "remote_service", "internal_spearphishing"],
    "Exfiltration": ["exfil", "data_exfiltration", "c2_exfil", "dns_tunnel", "ftp_exfil"]
}

with open("tactic_map.json", "w") as f:
    json.dump(tactic_map, f, indent=4)
print("tactic_map.json created.")
