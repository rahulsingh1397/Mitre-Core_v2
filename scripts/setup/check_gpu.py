import torch

print(f"PyTorch: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"Capability: {torch.cuda.get_device_capability(0)}")
    print(f"CUDA version: {torch.version.cuda}")
else:
    print("No GPU available")
