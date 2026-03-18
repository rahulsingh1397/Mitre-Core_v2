import pandas as pd
import os
import glob
import subprocess

def verify_logs():
    csv_files = glob.glob("results/*.csv")
    print(f"Found {len(csv_files)} result files.")
    
    # Try getting git commit hash
    try:
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
    except:
        commit_hash = "no_git_repo"
        
    print(f"Current commit hash: {commit_hash}")
    
    # Check if we generated all figures
    fig_files = glob.glob("figures/*.pdf")
    print(f"Generated {len(fig_files)} figures:")
    for f in fig_files:
        print(f" - {f}")
        
if __name__ == "__main__":
    verify_logs()

