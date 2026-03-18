"""
Complete MITRE ATT&CK Tactic Mapper for MITRE-CORE
Provides comprehensive tactic coverage for all attack types across datasets.
"""

from typing import Dict, Set, Optional, Tuple
import pandas as pd
import numpy as np


class MITRETacticMapper:
    """
    Comprehensive MITRE ATT&CK tactic mapping covering all 14 tactics.
    
    Tactics covered:
    1. Reconnaissance
    2. Resource Development
    3. Initial Access
    4. Execution
    5. Persistence
    6. Privilege Escalation
    7. Defense Evasion
    8. Credential Access
    9. Discovery
    10. Lateral Movement
    11. Collection
    12. Command and Control
    13. Exfiltration
    14. Impact
    """
    
    def __init__(self):
        # Complete MITRE ATT&CK v14 tactic mapping
        self.tactic_hierarchy = {
            'Reconnaissance': {
                'priority': 1,
                'description': 'Gathering information to target',
                'attack_patterns': [
                    'scan', 'portscan', 'portsweep', 'ipsweep', 'satan', 'nmap',
                    'recon', 'reconnaissance', 'discovery', 'host_discovery',
                    'network_sniffing', 'passive_dns', 'whois', 'dns_enumeration'
                ]
            },
            'Resource Development': {
                'priority': 2,
                'description': 'Establishing resources to support operations',
                'attack_patterns': [
                    'acquire_infrastructure', 'compromise_infrastructure',
                    'develop_capabilities', 'obtain_capabilities',
                    'upload_malware', 'build_arsenal'
                ]
            },
            'Initial Access': {
                'priority': 3,
                'description': 'Trying to get into your network',
                'attack_patterns': [
                    'exploit', 'back', 'phf', 'imap', 'land', 'sql_injection',
                    'sql', 'xss', 'injection', 'exploit_public_facing',
                    'external_remote_service', 'phishing', 'supply_chain',
                    'trusted_relationship', 'valid_accounts'
                ]
            },
            'Execution': {
                'priority': 4,
                'description': 'Trying to run malicious code',
                'attack_patterns': [
                    'shellcode', 'buffer_overflow', 'loadmodule', 'perl',
                    'execution', 'command_execution', 'user_execution',
                    'scripting', 'powershell', 'python', 'bash',
                    'fuzzers', 'analysis', 'generic', 'webshell'
                ]
            },
            'Persistence': {
                'priority': 5,
                'description': 'Trying to maintain their foothold',
                'attack_patterns': [
                    'rootkit', 'backdoor', 'create_account', 'local_account',
                    'domain_account', 'web_shell', 'modify_authentication',
                    'hijack_execution_flow', 'bootkit', 'create_service',
                    'scheduled_task', 'registry_run_keys', 'startup_folder'
                ]
            },
            'Privilege Escalation': {
                'priority': 6,
                'description': 'Trying to gain higher-level permissions',
                'attack_patterns': [
                    'privilege_escalation', 'elevate', 'sudo', 'sudoers',
                    'process_injection', 'token_impersonation',
                    'access_token_manipulation', 'bypass_user_account_control',
                    'elevated_execution'
                ]
            },
            'Defense Evasion': {
                'priority': 7,
                'description': 'Trying to avoid being detected',
                'attack_patterns': [
                    'rootkit', 'hidden', 'obfuscated', 'encrypted',
                    'packed', 'packed_malware', 'vm_aware', 'sandbox_aware',
                    'disable_security_tools', 'indicator_removal',
                    'clear_logs', 'timestomp', 'masquerading'
                ]
            },
            'Credential Access': {
                'priority': 8,
                'description': 'Stealing account names and passwords',
                'attack_patterns': [
                    'brute', 'bruteforce', 'crack', 'password', 'credential',
                    'guess_passwd', 'ftp_write', 'patator', 'ssh_patator',
                    'ftp_patator', 'credential_dumping', 'lsass',
                    'kerberoasting', 'credential_harvesting',
                    'heartbleed', 'ssl_heartbeat'
                ]
            },
            'Discovery': {
                'priority': 9,
                'description': 'Trying to figure out your environment',
                'attack_patterns': [
                    'system_information_discovery', 'system_network_configuration',
                    'account_discovery', 'software_discovery',
                    'process_discovery', 'network_service_scanning',
                    'file_and_directory_discovery', 'remote_system_discovery'
                ]
            },
            'Lateral Movement': {
                'priority': 10,
                'description': 'Moving through your environment',
                'attack_patterns': [
                    'lateral', 'move', 'multihop', 'worm', 'worms',
                    'remote_services', 'ssh', 'rdp', 'smb',
                    'pass_the_hash', 'pass_the_ticket',
                    'remote_file_copy', 'taint_shared_content'
                ]
            },
            'Collection': {
                'priority': 11,
                'description': 'Gathering data of interest',
                'attack_patterns': [
                    'spy', 'collection', 'data_staged', 'data_compressed',
                    'screen_capture', 'input_capture', 'clipboard_data',
                    'audio_capture', 'video_capture', 'email_collection',
                    'data_from_local_system', 'data_from_network'
                ]
            },
            'Command and Control': {
                'priority': 12,
                'description': 'Communicating with compromised systems',
                'attack_patterns': [
                    'bot', 'mirai', 'c2', 'command_and_control',
                    'warezclient', 'warezmaster', 'gafgyt', 'tsunami',
                    'hajime', 'reaper', 'satori', 'mozi',
                    'application_layer_protocol', 'web_protocol',
                    'dns', 'encrypted_channel', 'data_encoding'
                ]
            },
            'Exfiltration': {
                'priority': 13,
                'description': 'Stealing data',
                'attack_patterns': [
                    'exfiltration', 'exfil', 'data_exfiltration',
                    'over_c2_channel', 'over_alternative_protocol',
                    'web_service', 'cloud_storage', 'data_transfer_size_limits'
                ]
            },
            'Impact': {
                'priority': 14,
                'description': 'Manipulate, interrupt, or destroy systems',
                'attack_patterns': [
                    'dos', 'ddos', 'neptune', 'smurf', 'pod', 'teardrop',
                    'hulk', 'goldeneye', 'slowloris', 'slowhttptest',
                    'data_destruction', 'disk_content_wipe',
                    'account_access_removal', 'service_stop',
                    'resource_hijacking', 'data_encrypted_for_impact',
                    'defacement', 'ransomware'
                ]
            }
        }
        
        # Build reverse lookup: attack pattern -> tactic
        self.attack_to_tactic = {}
        for tactic, info in self.tactic_hierarchy.items():
            for pattern in info['attack_patterns']:
                self.attack_to_tactic[pattern.lower()] = tactic
    
    def map_attack_to_tactic(self, attack_label: str, confidence_threshold: float = 0.8) -> Tuple[str, float]:
        """
        Map an attack label to MITRE tactic with confidence score.
        
        Args:
            attack_label: The attack label/category
            confidence_threshold: Minimum confidence for valid mapping
            
        Returns:
            Tuple of (tactic_name, confidence_score)
        """
        label_lower = str(attack_label).lower().strip()
        
        # Direct match
        if label_lower in self.attack_to_tactic:
            return self.attack_to_tactic[label_lower], 1.0
        
        # Substring matching with scoring
        best_match = None
        best_confidence = 0.0
        
        for pattern, tactic in self.attack_to_tactic.items():
            # Check if pattern is in label or label is in pattern
            if pattern in label_lower:
                # Calculate confidence based on pattern length relative to label
                confidence = len(pattern) / len(label_lower)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = tactic
            elif label_lower in pattern:
                confidence = len(label_lower) / len(pattern)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = tactic
        
        if best_match and best_confidence >= confidence_threshold:
            return best_match, best_confidence
        
        # Fuzzy matching for common abbreviations
        fuzzy_mappings = self._get_fuzzy_mappings()
        if label_lower in fuzzy_mappings:
            return fuzzy_mappings[label_lower], 0.9
        
        return 'Unknown', 0.0
    
    def _get_fuzzy_mappings(self) -> Dict[str, str]:
        """Get common abbreviation and fuzzy mappings."""
        return {
            'normal': 'None',
            'benign': 'None',
            'clean': 'None',
            'scan': 'Reconnaissance',
            'probe': 'Reconnaissance',
            'r2l': 'Initial Access',  # Remote to Local
            'u2r': 'Privilege Escalation',  # User to Root
            'u2l': 'Lateral Movement',
            'dos': 'Impact',
            'ddos': 'Impact',
            'botnet': 'Command and Control',
            'cnc': 'Command and Control',
            'c&c': 'Command and Control',
            'infiltration': 'Lateral Movement',
            'web attack': 'Initial Access',
            'ftp': 'Credential Access',
            'ssh': 'Credential Access',
            'sql': 'Initial Access',
            'xss': 'Execution',
        }
    
    def get_tactic_chain(self, attack_sequence: list) -> list:
        """
        Get ordered tactic chain from a sequence of attacks.
        
        Args:
            attack_sequence: List of attack labels in temporal order
            
        Returns:
            Ordered list of (tactic, confidence) tuples
        """
        tactic_sequence = []
        for attack in attack_sequence:
            tactic, confidence = self.map_attack_to_tactic(attack)
            tactic_sequence.append((tactic, confidence))
        
        # Remove duplicates while preserving order (kill chain progression)
        seen = set()
        unique_chain = []
        for tactic, confidence in tactic_sequence:
            if tactic != 'None' and tactic != 'Unknown' and tactic not in seen:
                seen.add(tactic)
                unique_chain.append((tactic, confidence))
        
        return unique_chain
    
    def validate_tactic_coverage(self, df: pd.DataFrame, label_col: str = 'label') -> Dict:
        """
        Validate tactic coverage for a dataset.
        
        Args:
            df: DataFrame with attack labels
            label_col: Column containing attack labels
            
        Returns:
            Dictionary with coverage statistics
        """
        unique_labels = df[label_col].unique()
        
        coverage = {
            'total_unique_labels': len(unique_labels),
            'mapped_tactics': set(),
            'unmapped_labels': [],
            'tactic_distribution': {},
            'coverage_percentage': 0.0
        }
        
        for label in unique_labels:
            tactic, confidence = self.map_attack_to_tactic(label)
            
            if tactic == 'Unknown' or confidence < 0.5:
                coverage['unmapped_labels'].append(label)
            else:
                coverage['mapped_tactics'].add(tactic)
                coverage['tactic_distribution'][tactic] = \
                    coverage['tactic_distribution'].get(tactic, 0) + 1
        
        # Calculate coverage metrics
        total_tactics = len(self.tactic_hierarchy)
        covered_tactics = len(coverage['mapped_tactics'])
        coverage['coverage_percentage'] = (covered_tactics / total_tactics) * 100
        coverage['mapped_tactics'] = list(coverage['mapped_tactics'])
        
        return coverage
    
    def get_dataset_specific_mappings(self, dataset_name: str) -> Dict[str, str]:
        """Get dataset-specific attack to tactic mappings."""
        mappings = {
            'nsl_kdd': {
                'neptune': 'Impact',
                'smurf': 'Impact',
                'pod': 'Impact',
                'back': 'Initial Access',
                'teardrop': 'Impact',
                'ipsweep': 'Reconnaissance',
                'portsweep': 'Reconnaissance',
                'satan': 'Reconnaissance',
                'nmap': 'Reconnaissance',
                'guess_passwd': 'Credential Access',
                'ftp_write': 'Lateral Movement',
                'multihop': 'Lateral Movement',
                'phf': 'Initial Access',
                'spy': 'Collection',
                'buffer_overflow': 'Execution',
                'rootkit': 'Persistence',
                'loadmodule': 'Execution',
                'perl': 'Execution',
                'warezclient': 'Command and Control',
                'warezmaster': 'Command and Control',
                'imap': 'Initial Access',
                'land': 'Impact',
                'normal': 'None'
            },
            'unsw_nb15': {
                'Fuzzers': 'Execution',
                'Analysis': 'Collection',
                'Backdoor': 'Persistence',
                'DoS': 'Impact',
                'Exploits': 'Initial Access',
                'Generic': 'Initial Access',
                'Reconnaissance': 'Reconnaissance',
                'Shellcode': 'Execution',
                'Worms': 'Lateral Movement',
                'Normal': 'None'
            },
            'cicids2017': self._build_cicids2017_mapping(),
            'cse_cic_ids2018': self._build_cse_cic_mapping(),
            'ton_iot': self._build_ton_iot_mapping(),
            'cicapt_iiot': self._build_cicapt_mapping(),
            'datasense_iiot': self._build_datasense_mapping(),
            'linux_apt': self._build_linux_apt_mapping()
        }
        
        return mappings.get(dataset_name.lower(), {})
    
    def _build_cicids2017_mapping(self) -> Dict[str, str]:
        """Build comprehensive CICIDS2017 mapping."""
        return {
            'BENIGN': 'None',
            'FTP-Patator': 'Credential Access',
            'SSH-Patator': 'Credential Access',
            'DoS slowloris': 'Impact',
            'DoS Slowhttptest': 'Impact',
            'DoS Hulk': 'Impact',
            'DoS GoldenEye': 'Impact',
            'Heartbleed': 'Credential Access',
            'Web Attack - Brute Force': 'Credential Access',
            'Web Attack - XSS': 'Execution',
            'Web Attack - Sql Injection': 'Initial Access',
            'Infiltration': 'Lateral Movement',
            'Bot': 'Command and Control',
            'PortScan': 'Reconnaissance',
            'DDoS': 'Impact'
        }
    
    def _build_cse_cic_mapping(self) -> Dict[str, str]:
        """Build comprehensive CSE-CIC-IDS2018 mapping."""
        return {
            'Benign': 'None',
            'Bot': 'Command and Control',
            'Brute Force -Web': 'Credential Access',
            'Brute Force -XSS': 'Execution',
            'Brute Force -SQL': 'Initial Access',
            'DoS attacks-GoldenEye': 'Impact',
            'DoS attacks-Hulk': 'Impact',
            'DoS attacks-SlowHTTPTest': 'Impact',
            'DoS attacks-Slowloris': 'Impact',
            'FTP-BruteForce': 'Credential Access',
            'SSH-BruteForce': 'Credential Access',
            'Infilteration': 'Lateral Movement',
            'SQL Injection': 'Initial Access'
        }
    
    def _build_ton_iot_mapping(self) -> Dict[str, str]:
        """Build comprehensive TON_IoT mapping."""
        return {
            'normal': 'None',
            'backdoor': 'Persistence',
            'ddos': 'Impact',
            'dos': 'Impact',
            'injection': 'Initial Access',
            'mitm': 'Collection',
            'password': 'Credential Access',
            'ransomware': 'Impact',
            'scanning': 'Reconnaissance',
            'xss': 'Execution'
        }
    
    def _build_cicapt_mapping(self) -> Dict[str, str]:
        """Build comprehensive CICAPT-IIoT mapping."""
        return {
            'Normal': 'None',
            'PortScan': 'Reconnaissance',
            'DDoS': 'Impact',
            'DoS': 'Impact',
            'MITM': 'Collection',
            'Injection': 'Initial Access',
            'Password': 'Credential Access',
            'Ransomware': 'Impact',
            'XSS': 'Execution',
            'Backdoor': 'Persistence'
        }
    
    def _build_datasense_mapping(self) -> Dict[str, str]:
        """Build comprehensive DataSense IIoT mapping."""
        return {
            'Normal': 'None',
            'Benign': 'None',
            'Mirai': 'Command and Control',
            'Mirai-Greeth': 'Command and Control',
            'DoS-Syn': 'Impact',
            'DDoS-UDP': 'Impact',
            'Recon-PortScan': 'Reconnaissance',
            'PortScan': 'Reconnaissance',
            'BruteForce': 'Credential Access',
            'WebAttack': 'Initial Access',
            'XSS': 'Execution',
            'Injection': 'Initial Access'
        }
    
    def _build_linux_apt_mapping(self) -> Dict[str, str]:
        """Build comprehensive Linux APT mapping."""
        return {
            'Normal': 'None',
            'Persistence': 'Persistence',
            'Discovery': 'Discovery',
            'LateralMovement': 'Lateral Movement',
            'CredentialAccess': 'Credential Access',
            'Execution': 'Execution',
            'CommandAndControl': 'Command and Control',
            'Exfiltration': 'Exfiltration',
            'DefenseEvasion': 'Defense Evasion',
            'PrivilegeEscalation': 'Privilege Escalation'
        }


# Global mapper instance
_global_mapper = None


def get_mapper() -> MITRETacticMapper:
    """Get global MITRE tactic mapper instance."""
    global _global_mapper
    if _global_mapper is None:
        _global_mapper = MITRETacticMapper()
    return _global_mapper


def map_attack(attack_label: str) -> str:
    """Convenience function to map attack to tactic."""
    mapper = get_mapper()
    tactic, _ = mapper.map_attack_to_tactic(attack_label)
    return tactic


def validate_dataset_tactics(df: pd.DataFrame, label_col: str = 'label') -> Dict:
    """Validate tactic coverage for a dataset."""
    mapper = get_mapper()
    return mapper.validate_tactic_coverage(df, label_col)


# Enhanced mappings for modern_loader.py
def get_enhanced_modern_tactic_mapping() -> Dict[str, str]:
    """
    Enhanced tactic mapping covering all 14 MITRE ATT&CK tactics
    for modern IoT/IIoT datasets.
    """
    return {
        # None/Normal
        'normal': 'None',
        'benign': 'None',
        'clean': 'None',
        
        # Reconnaissance
        'recon': 'Reconnaissance',
        'reconnaissance': 'Reconnaissance',
        'portscan': 'Reconnaissance',
        'port_scan': 'Reconnaissance',
        'scan': 'Reconnaissance',
        'probe': 'Reconnaissance',
        'host_discovery': 'Reconnaissance',
        'network_scan': 'Reconnaissance',
        
        # Resource Development
        'setup': 'Resource Development',
        'infrastructure': 'Resource Development',
        
        # Initial Access
        'web': 'Initial Access',
        'sql': 'Initial Access',
        'sql_injection': 'Initial Access',
        'xss': 'Execution',  # Cross-site scripting is execution
        'injection': 'Initial Access',
        'exploit': 'Initial Access',
        'ftp_write': 'Initial Access',
        
        # Execution
        'shellcode': 'Execution',
        'script': 'Execution',
        'malware': 'Execution',
        'payload': 'Execution',
        'fuzzers': 'Execution',
        'analysis': 'Collection',  # Analysis attacks often collect data
        
        # Persistence
        'backdoor': 'Persistence',
        'rootkit': 'Persistence',
        'persistence': 'Persistence',
        'startup': 'Persistence',
        'registry': 'Persistence',
        
        # Privilege Escalation
        'privilege': 'Privilege Escalation',
        'escalation': 'Privilege Escalation',
        'sudo': 'Privilege Escalation',
        'admin': 'Privilege Escalation',
        
        # Defense Evasion
        'evasion': 'Defense Evasion',
        'hidden': 'Defense Evasion',
        'obfuscated': 'Defense Evasion',
        'packed': 'Defense Evasion',
        'vm_aware': 'Defense Evasion',
        'rootkit': 'Defense Evasion',  # Rootkit also evades detection
        
        # Credential Access
        'brute': 'Credential Access',
        'bruteforce': 'Credential Access',
        'password': 'Credential Access',
        'credential': 'Credential Access',
        'patator': 'Credential Access',
        'heartbleed': 'Credential Access',
        
        # Discovery
        'discovery': 'Discovery',
        'system_info': 'Discovery',
        'account_discovery': 'Discovery',
        'software_discovery': 'Discovery',
        
        # Lateral Movement
        'lateral': 'Lateral Movement',
        'worm': 'Lateral Movement',
        'worms': 'Lateral Movement',
        'multihop': 'Lateral Movement',
        'spread': 'Lateral Movement',
        'infiltration': 'Lateral Movement',
        
        # Collection
        'collection': 'Collection',
        'spy': 'Collection',
        'mitm': 'Collection',
        'sniff': 'Collection',
        'capture': 'Collection',
        'data_staged': 'Collection',
        
        # Command and Control
        'mirai': 'Command and Control',
        'bot': 'Command and Control',
        'botnet': 'Command and Control',
        'cnc': 'Command and Control',
        'c2': 'Command and Control',
        'command_and_control': 'Command and Control',
        'gafgyt': 'Command and Control',
        'tsunami': 'Command and Control',
        'hajime': 'Command and Control',
        'reaper': 'Command and Control',
        'satori': 'Command and Control',
        'mozi': 'Command and Control',
        'warezclient': 'Command and Control',
        'warezmaster': 'Command and Control',
        
        # Exfiltration
        'exfiltration': 'Exfiltration',
        'exfil': 'Exfiltration',
        'data_theft': 'Exfiltration',
        'upload': 'Exfiltration',
        
        # Impact
        'dos': 'Impact',
        'ddos': 'Impact',
        'denial': 'Impact',
        'service': 'Impact',
        'flood': 'Impact',
        'slowloris': 'Impact',
        'goldeneye': 'Impact',
        'hulk': 'Impact',
        'neptune': 'Impact',
        'smurf': 'Impact',
        'pod': 'Impact',
        'teardrop': 'Impact',
        'land': 'Impact',
        'ransomware': 'Impact',
        'wiper': 'Impact',
        'destruction': 'Impact'
    }


if __name__ == "__main__":
    # Test the mapper
    mapper = MITRETacticMapper()
    
    test_attacks = [
        'Mirai-Greeth',
        'DoS-Syn',
        'Recon-PortScan',
        'PortScan',
        'BruteForce',
        'SQL Injection',
        'XSS',
        'normal',
        'Backdoor',
        'Infiltration',
        'UnknownAttack'
    ]
    
    print("MITRE ATT&CK Tactic Mapping Test:")
    print("=" * 60)
    for attack in test_attacks:
        tactic, confidence = mapper.map_attack_to_tactic(attack)
        print(f"{attack:20} -> {tactic:25} (confidence: {confidence:.2f})")
    
    print("\n" + "=" * 60)
    print(f"Total tactics covered: {len(mapper.tactic_hierarchy)}")
    print("Tactics:", list(mapper.tactic_hierarchy.keys()))
