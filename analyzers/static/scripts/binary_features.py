import r2pipe
import sys


def extract_binary_features(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    cfg = r2.cmd("agf")  # Get control flow graph (CFG)
    return cfg


def main():
    binary_path = sys.argv[1]
    print("Starting binary_features.py script: ",binary_path)
    result = extract_binary_features(binary_path)
    print("Binary Features (CFG):")
    print(result)
    print("Termination: binary_features.py script completed successfully.")


if __name__ == "__main__":
    main()
