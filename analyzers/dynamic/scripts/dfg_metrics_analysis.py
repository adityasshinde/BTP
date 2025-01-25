import r2pipe
import json
import networkx as nx
from collections import Counter

# 🔥 Suspicious API Patterns (Common in Malware & Packers)
SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualProtect",
    "CreateRemoteThread",
    "LoadLibrary",
    "GetProcAddress",
    "WriteProcessMemory",
}


def analyze_binary_r2(file_path):
    """
    Use Radare2 to analyze the binary and extract function metadata.
    """
    try:
        r2 = r2pipe.open(file_path)
        r2.cmd("aaa")  # Perform full binary analysis

        # Get function list
        functions = r2.cmd("aflj")
        function_data = json.loads(functions)

        if not function_data:
            raise ValueError("No functions found in binary")

        return function_data
    except Exception as e:
        return {"error": str(e)}


def construct_dfg_r2(function_data):
    """
    Construct the Data Flow Graph (DFG) using Radare2's function analysis.
    """
    G = nx.DiGraph()
    suspicious_functions = set()
    indirect_calls = set()

    for func in function_data:
        func_name = func.get("name", "unknown")
        func_addr = func.get("offset", 0)
        G.add_node(func_addr, name=func_name)

        # Detect malware-relevant functions
        if any(api in func_name for api in SUSPICIOUS_APIS):
            suspicious_functions.add(func_name)

        # Get function control flow (basic block xrefs)
        xrefs = func.get("callrefs", [])
        for xref in xrefs:
            target_addr = xref.get("addr", None)
            call_type = xref.get("type", "")

            if target_addr:
                G.add_edge(func_addr, target_addr)
                if call_type == "ind":  # Indirect calls (often used in obfuscation)
                    indirect_calls.add((func_addr, target_addr))

    return G, suspicious_functions, indirect_calls


def compute_dominance_tree(G):
    """
    Compute dominance tree from DFG.
    """
    try:
        if not G.nodes:
            return []

        dom_tree = nx.immediate_dominators(G, list(G.nodes)[0])
        dominance_edges = [
            f"{dom_tree[node]} -> {node}" for node in dom_tree if node != dom_tree[node]
        ]
        return dominance_edges
    except Exception:
        return []


def detect_anomalies(G):
    """
    Detect anomalies based on graph topology:
    - Unusual connectivity (Highly connected nodes = possible unpacking loops)
    - Dead code detection (Disconnected nodes)
    - Packed binaries (Very high edge-to-node ratio)
    """
    anomalies = []

    # Packed binaries have a high edge/node ratio
    if G.number_of_nodes() > 0 and (G.number_of_edges() / G.number_of_nodes()) > 5:
        anomalies.append("High edge-to-node ratio (Possible packed binary)")

    # Detect functions with excessive outgoing edges (common in obfuscation)
    node_degrees = dict(G.out_degree())
    max_degree = max(node_degrees.values()) if node_degrees else 0
    if max_degree > 15:
        anomalies.append(
            "Function with extremely high outgoing edges (Possible control flow obfuscation)"
        )

    # Find disconnected nodes (dead code detection)
    dead_code = [
        node for node in G.nodes if G.in_degree(node) == 0 and G.out_degree(node) == 0
    ]
    if dead_code:
        anomalies.append(
            f"Detected {len(dead_code)} isolated functions (Possible dead code)"
        )

    return anomalies


def analyze_dfg_metrics(file_path):
    """
    Perform full Data Flow Graph (DFG) analysis using r2pipe.
    """
    results = {
        "nodes": 0,
        "edges": 0,
        "dominance_tree": [],
        "suspicious_apis": [],
        "indirect_calls": [],
        "anomalies": [],
        "status": "pending",
    }

    try:
        function_data = analyze_binary_r2(file_path)
        if "error" in function_data:
            raise ValueError(function_data["error"])

        dfg, suspicious_functions, indirect_calls = construct_dfg_r2(function_data)

        results["nodes"] = dfg.number_of_nodes()
        results["edges"] = dfg.number_of_edges()
        results["dominance_tree"] = compute_dominance_tree(dfg)
        results["suspicious_apis"] = list(suspicious_functions)
        results["indirect_calls"] = [f"{src} -> {dst}" for src, dst in indirect_calls]
        results["anomalies"] = detect_anomalies(dfg)
        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


# Example usage
binary_path = "DroidCam.exe"
dfg_results = analyze_dfg_metrics(binary_path)
print(json.dumps(dfg_results, indent=4))
