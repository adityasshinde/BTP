import json
import sys
import r2pipe

def analyze_api_call_graph(binary_path, results_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")
    results = {"call_graph": r2.cmd("ag")}  # API call graph
    
    with open(results_path, "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    binary_path = sys.argv[1]
    results_path = sys.argv[2]
    analyze_api_call_graph(binary_path, results_path)
