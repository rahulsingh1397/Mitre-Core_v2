import matplotlib.pyplot as plt
import numpy as np

def plot_reliability_diagram(confidences: np.ndarray, accuracies: np.ndarray, 
                           n_bins: int = 10, save_path: str = None):
    """
    Plot reliability diagram for calibration visualization.
    """
    plt.figure(figsize=(8, 8))
    plt.plot([0, 1], [0, 1], "k--", label="Perfect Calibration")
    plt.plot(confidences, accuracies, "o-", label="Model")
    plt.xlabel("Confidence")
    plt.ylabel("Accuracy")
    plt.title("Reliability Diagram")
    plt.legend()
    
    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

