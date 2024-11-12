import json
import sys
import pefile
import r2pipe

def synthesize_semantics(binary_path, results_path):
    print("Synthesizing semantics for binary: {}".format(binary_path))
    results = {}
    
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all
    results["strings"] = r2.cmd("izz")  # Extract strings
    results["imports"] = r2.cmd("ii")   # Extract imports
    
    print(results)
    with open(results_path, "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    binary_path = sys.argv[1]
    results_path = sys.argv[2]
    synthesize_semantics(binary_path, results_path)
