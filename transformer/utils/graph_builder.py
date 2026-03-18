import torch
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging
import torch_geometric.data as pyg_data

logger = logging.getLogger(__name__)

class HeterogeneousGraphBuilder:
    """
    Builds a PyTorch Geometric HeteroData object from an alert DataFrame.
    """
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
        
        # Entity mappers
        self.ip_to_id = {}
        self.host_to_id = {}
        self.tactic_to_id = {}
        
    def build(self, df: pd.DataFrame) -> pyg_data.HeteroData:
        """
        Convert DataFrame to HeteroData graph.
        
        Node Types:
        - alert
        - ip
        - host
        - tactic
        
        Edge Types:
        - (alert, src_ip, ip)
        - (alert, dst_ip, ip)
        - (alert, runs_on, host)
        - (alert, has_tactic, tactic)
        - (alert, temporal, alert)
        """
        data = pyg_data.HeteroData()
        
        # Extract node features (simplified representation)
        num_alerts = len(df)
        
        # For simplicity in this dummy version, we just use random indices
        # In a real implementation, we would map categorical variables to IDs
        data['alert'].x = torch.randint(0, self.vocab_size, (num_alerts, 1))
        
        # Create entity mappings
        src_ips = df.get('SourceAddress', pd.Series([''] * num_alerts)).fillna('').values
        dst_ips = df.get('DestinationAddress', pd.Series([''] * num_alerts)).fillna('').values
        hosts = df.get('DeviceHostName', pd.Series([''] * num_alerts)).fillna('').values
        
        # Get unique entities
        unique_ips = set(src_ips) | set(dst_ips) - {''}
        unique_hosts = set(hosts) - {''}
        
        for ip in unique_ips:
            if ip not in self.ip_to_id:
                self.ip_to_id[ip] = len(self.ip_to_id)
                
        for host in unique_hosts:
            if host not in self.host_to_id:
                self.host_to_id[host] = len(self.host_to_id)
                
        # Define node features for entities
        if self.ip_to_id:
            data['ip'].x = torch.arange(len(self.ip_to_id)).view(-1, 1)
        else:
            data['ip'].x = torch.empty((0, 1), dtype=torch.long)
            
        if self.host_to_id:
            data['host'].x = torch.arange(len(self.host_to_id)).view(-1, 1)
        else:
            data['host'].x = torch.empty((0, 1), dtype=torch.long)
            
        # Tactic nodes
        data['tactic'].x = torch.empty((0, 1), dtype=torch.long)
        
        # Build edges
        src_edges = []
        dst_edges = []
        host_edges = []
        
        for i in range(num_alerts):
            src = src_ips[i]
            if src in self.ip_to_id:
                src_edges.append((i, self.ip_to_id[src]))
                
            dst = dst_ips[i]
            if dst in self.ip_to_id:
                dst_edges.append((i, self.ip_to_id[dst]))
                
            host = hosts[i]
            if host in self.host_to_id:
                host_edges.append((i, self.host_to_id[host]))
                
        # Add edges to data object
        if src_edges:
            src_tensor = torch.tensor(src_edges, dtype=torch.long).t().contiguous()
            data['alert', 'src_ip', 'ip'].edge_index = src_tensor
        else:
            data['alert', 'src_ip', 'ip'].edge_index = torch.empty((2, 0), dtype=torch.long)
            
        if dst_edges:
            dst_tensor = torch.tensor(dst_edges, dtype=torch.long).t().contiguous()
            data['alert', 'dst_ip', 'ip'].edge_index = dst_tensor
        else:
            data['alert', 'dst_ip', 'ip'].edge_index = torch.empty((2, 0), dtype=torch.long)
            
        if host_edges:
            host_tensor = torch.tensor(host_edges, dtype=torch.long).t().contiguous()
            data['alert', 'runs_on', 'host'].edge_index = host_tensor
        else:
            data['alert', 'runs_on', 'host'].edge_index = torch.empty((2, 0), dtype=torch.long)
            
        # Add temporal edges (simplified sequential for now)
        temporal_edges = []
        if num_alerts > 1:
            for i in range(num_alerts - 1):
                temporal_edges.append((i, i+1))
                
        if temporal_edges:
            temporal_tensor = torch.tensor(temporal_edges, dtype=torch.long).t().contiguous()
            data['alert', 'temporal', 'alert'].edge_index = temporal_tensor
        else:
            data['alert', 'temporal', 'alert'].edge_index = torch.empty((2, 0), dtype=torch.long)
            
        # Tactic edges
        data['alert', 'has_tactic', 'tactic'].edge_index = torch.empty((2, 0), dtype=torch.long)
        
        return data
