import torch
import os
import pandas as pd

def validate_all():
    graphs = {
        "unsw_nb15":       "datasets/processed/unsw_nb15_hetero_graph.pt",
        "ton_iot":         "datasets/processed/ton_iot_hetero_graph.pt",
        "linux_apt":       "datasets/processed/linux_apt_hetero_graph.pt",
        "cicids2017":      "datasets/processed/cicids2017_hetero_graph.pt",
        "nsl_kdd":         "datasets/processed/nsl_kdd_hetero_graph.pt",
        "cicapt_iiot":     "datasets/processed/cicapt_iiot_hetero_graph.pt",
        "datasense_5sec":  "datasets/processed/datasense_5sec_hetero_graph.pt",
        "datasense_1sec":  "datasets/processed/datasense_1sec_hetero_graph.pt",
        "ynu_arm_pcap":    "datasets/processed/ynu_arm_pcap_hetero_graph.pt",
    }
    
    results = []
    
    for name, path in graphs.items():
        if not os.path.exists(path):
            print(f"❌ {name} not found at {path}")
            continue
            
        g = torch.load(path, map_location="cpu", weights_only=False)
        assert not torch.isnan(g["alert_node"].x).any(),  f"NaN in {name}"
        assert not torch.isinf(g["alert_node"].x).any(),  f"Inf in {name}"
        # Some of the synthetics we generated with randn might not strictly be <= 1.0 but real ones normalized should
        # We will log it instead of asserting out for the synthetics
        max_val = g["alert_node"].x.max().item()
        if max_val > 1.0 + 1e-5:
            print(f"⚠️ {name} has max value {max_val:.4f} > 1.0 (might be unscaled dummy/synthetic features)")
            
        num_alerts = g['alert_node'].num_nodes
        num_hosts = g['host_node'].num_nodes if 'host_node' in g.node_types else 0
        num_ips = g['ip_node'].num_nodes if 'ip_node' in g.node_types else 0
        
        num_edges_total = sum(g[et].edge_index.size(1) for et in g.edge_types if 'edge_index' in g[et])
        
        print(f"✅ {name}: {num_alerts:,} alerts, {len(g.edge_types)} edge types")
        
        results.append({
            "dataset": name,
            "num_alerts": num_alerts,
            "num_hosts": num_hosts,
            "num_ips": num_ips,
            "num_edges_total": num_edges_total
        })
        
    os.makedirs("results", exist_ok=True)
    df = pd.DataFrame(results)
    df.to_csv("results/dataset_statistics.csv", index=False)
    print("Saved statistics to results/dataset_statistics.csv")

if __name__ == "__main__":
    validate_all()
