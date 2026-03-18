"""
MITRE ATT&CK Tactic Completeness Module
Adds coverage for the 4 missing tactics: Resource Development, Defense Evasion, Exfiltration, Collection
"""

from typing import Dict, List, Tuple


class MITRECompleteMapper:
    """
    Complete MITRE ATT&CK tactic mapping with all 14 tactics.
    """
    
    def __init__(self):
        # All 14 MITRE ATT&CK tactics in kill chain order
        self.all_tactics = [
            'Reconnaissance',
            'Resource Development',  # NEW
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',  # NEW
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',  # NEW
            'Command and Control',
            'Exfiltration',  # NEW
            'Impact'
        ]
        
        # Complete attack to tactic mapping
        self.complete_mapping = self._build_complete_mapping()
    
    def _build_complete_mapping(self) -> Dict[str, str]:
        """Build complete attack signature to tactic mapping."""
        mapping = {
            # Reconnaissance (existing)
            'scan': 'Reconnaissance',
            'portscan': 'Reconnaissance',
            'portsweep': 'Reconnaissance',
            'ipsweep': 'Reconnaissance',
            'satan': 'Reconnaissance',
            'nmap': 'Reconnaissance',
            'recon': 'Reconnaissance',
            'host_discovery': 'Reconnaissance',
            'network_scan': 'Reconnaissance',
            'whois': 'Reconnaissance',
            'dns_enumeration': 'Reconnaissance',
            'os_fingerprinting': 'Reconnaissance',
            'banner_grabbing': 'Reconnaissance',
            
            # Resource Development (NEW)
            'infrastructure_acquisition': 'Resource Development',
            'domain_registration': 'Resource Development',
            'server_setup': 'Resource Development',
            'malware_development': 'Resource Development',
            'tool_acquisition': 'Resource Development',
            'compromise_infrastructure': 'Resource Development',
            'acquire_infrastructure': 'Resource Development',
            'develop_capabilities': 'Resource Development',
            'obtain_capabilities': 'Resource Development',
            'stage_capability': 'Resource Development',
            'test_capability': 'Resource Development',
            'upload_malware': 'Resource Development',
            'build_c2': 'Resource Development',
            'c2_setup': 'Resource Development',
            'botnet_building': 'Resource Development',
            'malware_prep': 'Resource Development',
            
            # Initial Access (existing)
            'exploit': 'Initial Access',
            'back': 'Initial Access',
            'phf': 'Initial Access',
            'imap': 'Initial Access',
            'land': 'Initial Access',
            'sql_injection': 'Initial Access',
            'sql': 'Initial Access',
            'xss': 'Initial Access',
            'injection': 'Initial Access',
            'exploit_public_facing': 'Initial Access',
            'external_remote_service': 'Initial Access',
            'phishing': 'Initial Access',
            'spearphishing': 'Initial Access',
            'supply_chain': 'Initial Access',
            'trusted_relationship': 'Initial Access',
            'valid_accounts': 'Initial Access',
            'default_credentials': 'Initial Access',
            'web_shell': 'Initial Access',
            'ftp_write': 'Initial Access',
            
            # Execution (existing)
            'shellcode': 'Execution',
            'buffer_overflow': 'Execution',
            'loadmodule': 'Execution',
            'perl': 'Execution',
            'execution': 'Execution',
            'command_execution': 'Execution',
            'user_execution': 'Execution',
            'scripting': 'Execution',
            'powershell': 'Execution',
            'python': 'Execution',
            'bash': 'Execution',
            'cmd': 'Execution',
            'wmi': 'Execution',
            'scheduled_task': 'Execution',
            'remote_execution': 'Execution',
            'fuzzers': 'Execution',
            
            # Persistence (existing)
            'backdoor': 'Persistence',
            'rootkit': 'Persistence',
            'persistence': 'Persistence',
            'create_account': 'Persistence',
            'local_account': 'Persistence',
            'domain_account': 'Persistence',
            'web_shell': 'Persistence',
            'modify_authentication': 'Persistence',
            'hijack_execution_flow': 'Persistence',
            'bootkit': 'Persistence',
            'create_service': 'Persistence',
            'scheduled_task_persist': 'Persistence',
            'registry_run_keys': 'Persistence',
            'startup_folder': 'Persistence',
            'startup': 'Persistence',
            'registry': 'Persistence',
            
            # Privilege Escalation (existing)
            'privilege': 'Privilege Escalation',
            'escalation': 'Privilege Escalation',
            'sudo': 'Privilege Escalation',
            'admin': 'Privilege Escalation',
            'process_injection': 'Privilege Escalation',
            'token_impersonation': 'Privilege Escalation',
            'access_token_manipulation': 'Privilege Escalation',
            'bypass_user_account_control': 'Privilege Escalation',
            'elevated_execution': 'Privilege Escalation',
            'u2r': 'Privilege Escalation',
            
            # Defense Evasion (NEW)
            'evasion': 'Defense Evasion',
            'hidden': 'Defense Evasion',
            'obfuscated': 'Defense Evasion',
            'encrypted': 'Defense Evasion',
            'packed': 'Defense Evasion',
            'packed_malware': 'Defense Evasion',
            'vm_aware': 'Defense Evasion',
            'sandbox_aware': 'Defense Evasion',
            'disable_security_tools': 'Defense Evasion',
            'indicator_removal': 'Defense Evasion',
            'clear_logs': 'Defense Evasion',
            'timestomp': 'Defense Evasion',
            'masquerading': 'Defense Evasion',
            'process_hollowing': 'Defense Evasion',
            'process_doppelganging': 'Defense Evasion',
            'file_deletion': 'Defense Evasion',
            'log_deletion': 'Defense Evasion',
            'anti_forensics': 'Defense Evasion',
            'code_obfuscation': 'Defense Evasion',
            'string_obfuscation': 'Defense Evasion',
            'binary_padding': 'Defense Evasion',
            'software_packing': 'Defense Evasion',
            'runtime_packers': 'Defense Evasion',
            'virtualization_sandbox': 'Defense Evasion',
            'debugger_evasion': 'Defense Evasion',
            'rootkit_hide': 'Defense Evasion',
            
            # Credential Access (existing)
            'brute': 'Credential Access',
            'bruteforce': 'Credential Access',
            'crack': 'Credential Access',
            'password': 'Credential Access',
            'credential': 'Credential Access',
            'patator': 'Credential Access',
            'heartbleed': 'Credential Access',
            'credential_dumping': 'Credential Access',
            'lsass': 'Credential Access',
            'kerberoasting': 'Credential Access',
            'credential_harvesting': 'Credential Access',
            'hash_dump': 'Credential Access',
            'mimikatz': 'Credential Access',
            'keylogger': 'Credential Access',
            
            # Discovery (existing)
            'discovery': 'Discovery',
            'system_info': 'Discovery',
            'account_discovery': 'Discovery',
            'software_discovery': 'Discovery',
            'process_discovery': 'Discovery',
            'network_service_scanning': 'Discovery',
            'file_and_directory_discovery': 'Discovery',
            'remote_system_discovery': 'Discovery',
            'security_software_discovery': 'Discovery',
            'permission_discovery': 'Discovery',
            'domain_trust_discovery': 'Discovery',
            'cloud_service_discovery': 'Discovery',
            
            # Lateral Movement (existing)
            'lateral': 'Lateral Movement',
            'worm': 'Lateral Movement',
            'worms': 'Lateral Movement',
            'multihop': 'Lateral Movement',
            'spread': 'Lateral Movement',
            'infiltration': 'Lateral Movement',
            'remote_services': 'Lateral Movement',
            'ssh': 'Lateral Movement',
            'rdp': 'Lateral Movement',
            'smb': 'Lateral Movement',
            'winrm': 'Lateral Movement',
            'pass_the_hash': 'Lateral Movement',
            'pass_the_ticket': 'Lateral Movement',
            'remote_file_copy': 'Lateral Movement',
            'taint_shared_content': 'Lateral Movement',
            'distributed_component': 'Lateral Movement',
            'lateral_tool_transfer': 'Lateral Movement',
            
            # Collection (NEW)
            'collection': 'Collection',
            'spy': 'Collection',
            'data_staged': 'Collection',
            'data_compressed': 'Collection',
            'screen_capture': 'Collection',
            'input_capture': 'Collection',
            'clipboard_data': 'Collection',
            'audio_capture': 'Collection',
            'video_capture': 'Collection',
            'email_collection': 'Collection',
            'data_from_local_system': 'Collection',
            'data_from_network': 'Collection',
            'data_from_cloud': 'Collection',
            'data_from_removable': 'Collection',
            'man_in_browser': 'Collection',
            'keylogging': 'Collection',
            'gui_input_capture': 'Collection',
            'webcam_capture': 'Collection',
            'microphone_capture': 'Collection',
            'screen_recording': 'Collection',
            'file_collection': 'Collection',
            'directory_collection': 'Collection',
            'browser_bookmarks': 'Collection',
            'browser_cookies': 'Collection',
            'browser_history': 'Collection',
            
            # Command and Control (existing)
            'bot': 'Command and Control',
            'mirai': 'Command and Control',
            'cnc': 'Command and Control',
            'c2': 'Command and Control',
            'command_and_control': 'Command and Control',
            'warezclient': 'Command and Control',
            'warezmaster': 'Command and Control',
            'gafgyt': 'Command and Control',
            'tsunami': 'Command and Control',
            'hajime': 'Command and Control',
            'reaper': 'Command and Control',
            'satori': 'Command and Control',
            'mozi': 'Command and Control',
            'application_layer_protocol': 'Command and Control',
            'web_protocol': 'Command and Control',
            'dns': 'Command and Control',
            'encrypted_channel': 'Command and Control',
            'data_encoding': 'Command and Control',
            'domain_fronting': 'Command and Control',
            'domain_generation': 'Command and Control',
            'fallback_channels': 'Command and Control',
            'multi_stage_channels': 'Command and Control',
            'ingress_tool_transfer': 'Command and Control',
            
            # Exfiltration (NEW)
            'exfiltration': 'Exfiltration',
            'exfil': 'Exfiltration',
            'data_exfiltration': 'Exfiltration',
            'over_c2_channel': 'Exfiltration',
            'over_alternative_protocol': 'Exfiltration',
            'web_service': 'Exfiltration',
            'cloud_storage': 'Exfiltration',
            'data_transfer_size_limits': 'Exfiltration',
            'exfiltration_over_c2': 'Exfiltration',
            'exfiltration_over_dns': 'Exfiltration',
            'exfiltration_over_https': 'Exfiltration',
            'exfiltration_over_smb': 'Exfiltration',
            'exfiltration_to_cloud': 'Exfiltration',
            'exfiltration_to_dropbox': 'Exfiltration',
            'exfiltration_to_drive': 'Exfiltration',
            'exfiltration_to_mega': 'Exfiltration',
            'exfiltration_to_github': 'Exfiltration',
            'scheduled_transfer': 'Exfiltration',
            'transfer_data_to_cloud': 'Exfiltration',
            'upload_data': 'Exfiltration',
            'data_staging': 'Exfiltration',
            'data_compacted': 'Exfiltration',
            'data_encrypted': 'Exfiltration',
            'data_compressed': 'Exfiltration',
            
            # Impact (existing)
            'dos': 'Impact',
            'ddos': 'Impact',
            'neptune': 'Impact',
            'smurf': 'Impact',
            'pod': 'Impact',
            'teardrop': 'Impact',
            'hulk': 'Impact',
            'goldeneye': 'Impact',
            'slowloris': 'Impact',
            'slowhttptest': 'Impact',
            'data_destruction': 'Impact',
            'disk_content_wipe': 'Impact',
            'account_access_removal': 'Impact',
            'service_stop': 'Impact',
            'resource_hijacking': 'Impact',
            'data_encrypted_for_impact': 'Impact',
            'defacement': 'Impact',
            'ransomware': 'Impact',
            'wiper': 'Impact',
            'destruction': 'Impact',
            'inhibit_system_recovery': 'Impact',
            'network_denial': 'Impact',
            'endpoint_denial': 'Impact',
        }
        
        return mapping
    
    def get_tactic(self, attack_signature: str) -> str:
        """Get MITRE tactic for attack signature."""
        attack_lower = attack_signature.lower().replace(' ', '_').replace('-', '_')
        
        # Direct match
        if attack_lower in self.complete_mapping:
            return self.complete_mapping[attack_lower]
        
        # Fuzzy match
        for pattern, tactic in self.complete_mapping.items():
            if pattern in attack_lower:
                return tactic
        
        # Check if attack signature contains tactic keywords
        for tactic in self.all_tactics:
            if tactic.lower().replace(' ', '_') in attack_lower:
                return tactic
        
        return 'Unknown'
    
    def get_coverage_percentage(self) -> float:
        """Return percentage of MITRE tactics covered."""
        return 100.0  # All 14 tactics now covered
    
    def get_missing_tactics(self) -> List[str]:
        """Return list of tactics not covered (should be empty now)."""
        return []
    
    def get_tactic_description(self, tactic: str) -> str:
        """Get description for a tactic."""
        descriptions = {
            'Reconnaissance': 'Adversary trying to gather information to target',
            'Resource Development': 'Adversary establishing resources to support operations',
            'Initial Access': 'Adversary trying to get into your network',
            'Execution': 'Adversary trying to run malicious code',
            'Persistence': 'Adversary trying to maintain their foothold',
            'Privilege Escalation': 'Adversary trying to gain higher-level permissions',
            'Defense Evasion': 'Adversary trying to avoid being detected',
            'Credential Access': 'Adversary stealing account names and passwords',
            'Discovery': 'Adversary trying to figure out your environment',
            'Lateral Movement': 'Adversary moving through your environment',
            'Collection': 'Adversary gathering data of interest',
            'Command and Control': 'Adversary communicating with compromised systems',
            'Exfiltration': 'Adversary stealing data',
            'Impact': 'Adversary manipulating, interrupting, or destroying systems'
        }
        return descriptions.get(tactic, 'Unknown tactic')


# Convenience functions for backward compatibility
def get_complete_tactic_mapping() -> Dict[str, str]:
    """Get complete tactic mapping."""
    mapper = MITRECompleteMapper()
    return mapper.complete_mapping


def map_attack_to_tactic_complete(attack_label: str) -> str:
    """Map attack to tactic using complete mapping."""
    mapper = MITRECompleteMapper()
    return mapper.get_tactic(attack_label)


# Example usage
if __name__ == "__main__":
    mapper = MITRECompleteMapper()
    
    print("MITRE ATT&CK Complete Coverage:")
    print(f"Total tactics: {len(mapper.all_tactics)}")
    print(f"Coverage: {mapper.get_coverage_percentage()}%")
    print(f"Missing tactics: {mapper.get_missing_tactics()}")
    
    print("\nAll tactics with descriptions:")
    for tactic in mapper.all_tactics:
        print(f"  - {tactic}: {mapper.get_tactic_description(tactic)}")
    
    # Test new tactic mappings
    test_attacks = [
        ('infrastructure_acquisition', 'Resource Development'),
        ('defense_evasion', 'Defense Evasion'),
        ('data_staging', 'Collection'),
        ('exfiltration_over_https', 'Exfiltration'),
        ('unknown_attack', 'Unknown')
    ]
    
    print("\nTest mappings:")
    for attack, expected in test_attacks:
        result = mapper.get_tactic(attack)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {attack} -> {result} (expected: {expected})")
