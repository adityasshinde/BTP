import json
import sys
import r2pipe

def analyze_initial_api_behaviors(binary_path, results_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    initial_calls = r2.cmd("ii")  # Imports as initial behaviors
    
    results = {"initial_apis": initial_calls}
    
    with open(results_path, "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    binary_path = sys.argv[1]
    results_path = sys.argv[2]
    analyze_initial_api_behaviors(binary_path, results_path)
