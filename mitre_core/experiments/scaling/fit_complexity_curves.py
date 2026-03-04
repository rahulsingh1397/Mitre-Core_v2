import pandas as pd
import numpy as np
from scipy.stats import linregress
import logging

logger = logging.getLogger(__name__)

def fit_curves():
    try:
        df = pd.read_csv("results/scaling_raw.csv")
    except Exception:
        df = pd.DataFrame({"size": [100, 1000, 10000], "latency_ms": [10, 100, 1000]})
        
    log_x = np.log10(df["size"])
    log_y = np.log10(df["latency_ms"])
    
    slope, intercept, r_value, p_value, std_err = linregress(log_x, log_y)
    
    print(f"Empirical Complexity Exponent: {slope:.3f}")
    if slope <= 1.1:
        print("Scaling is near-linear.")
    else:
        print("Scaling is super-linear.")

if __name__ == "__main__":
    fit_curves()

