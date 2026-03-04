import pandas as pd
import numpy as np
from annoy import AnnoyIndex
from sklearn.feature_extraction import FeatureHasher
import time

def optimized_correlation(n_events=5000):
    df = pd.DataFrame({
        "SourceAddress": [f"10.0.0.{i%100}" for i in range(n_events)],
        "DestinationAddress": [f"192.168.1.{i%50}" for i in range(n_events)],
        "SourceHostName": [f"host_{i%20}" for i in range(n_events)],
        "EndDate": pd.date_range("2023-01-01", periods=n_events, freq="min")
    })
    
    addresses = ["SourceAddress", "DestinationAddress"]
    usernames = ["SourceHostName"]
    
    start_time = time.time()
    
    text_data = []
    
    addr_data = df[addresses].astype(str).values
    user_data = df[usernames].astype(str).values
    
    for i in range(n_events):
        features = []
        for c, col in enumerate(addresses):
            val = addr_data[i, c]
            if val not in ["nan", "NIL", "UNKNOWN", "None", ""]:
                features.append(f"{col}={val}")
        for c, col in enumerate(usernames):
            val = user_data[i, c]
            if val not in ["nan", "NIL", "UNKNOWN", "None", ""]:
                features.append(f"{col}={val}")
        text_data.append(features)
        
    hasher = FeatureHasher(n_features=64, input_type="string")
    X = hasher.transform(text_data).toarray()
    
    timestamps = pd.to_datetime(df["EndDate"]).values.astype("datetime64[s]").astype(np.float64)
    t_min = np.nanmin(timestamps)
    t_max = np.nanmax(timestamps)
    if t_max > t_min:
        t_norm = (timestamps - t_min) / (t_max - t_min) * 10.0
    else:
        t_norm = np.zeros(n_events)
        
    X = np.hstack([X, t_norm.reshape(-1, 1)])
    dim = X.shape[1]
    
    annoy_idx = AnnoyIndex(dim, "angular")
    for i in range(n_events):
        annoy_idx.add_item(i, X[i])
        
    annoy_idx.build(10)
    
    candidates = set()
    
    k = min(50, n_events)
    for i in range(n_events):
        nn = annoy_idx.get_nns_by_item(i, k)
        for j in nn:
            if j > i:
                candidates.add((i, j))
                
    print(f"Time taken: {time.time() - start_time:.3f}s, Candidates generated: {len(candidates)}")

optimized_correlation()

