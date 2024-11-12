"""
Before running this script, install the following python modules using pip:
capstone, r2pipe, networkx, json, angr

Also, download Rdare2 from GitHub official repository and copy the path of it's "bin" folder in Environmental Variables.
"""

import json
import capstone
import angr
import r2pipe
import networkx as nx
from collections import Counter


# Helper function to save results to JSON
def save_results(results, filename="analysis_results.json"):
    if "control_flow_graph" in results:
        results["control_flow_graph"] = {
            "nodes": list(results["control_flow_graph"].nodes),
            "edges": list(results["control_flow_graph"].edges),
        }

    if "file_relation_graph" in results:
        results["file_relation_graph"] = {
            "nodes": list(results["file_relation_graph"].nodes),
            "edges": list(results["file_relation_graph"].edges),
        }

    # Save the results to a JSON file
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)


# 1. Exact Decompilation using radare2
def get_decompiled_functions(binary_path):
    print("Exact Decompilation starts...")
    r2 = r2pipe.open(binary_path)
    r2.cmd("aa")
    functions = r2.cmd("afl").splitlines()
    decompiled_functions = {}

    for func in functions:
        func_addr = func.split()[0]
        decompiled_code = r2.cmd(f"pdf @ {func_addr}")
        decompiled_functions[func_addr] = decompiled_code

    print("Exact Decompilation ends...")
    return decompiled_functions


# 2. Opcode Statistics using Capstone disassembler
def get_opcode_statistics(binary_path):
    print("OP Code Generation starts...")
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    md = capstone.Cs(
        capstone.CS_ARCH_X86, capstone.CS_MODE_64
    )  # Adjust for architecture
    opcode_stats = Counter()

    for insn in md.disasm(binary_data, 0x1000):  # Assuming binary starts at 0x1000
        opcode_stats[insn.mnemonic] += 1

    print("OP Code Generation ends...")
    return dict(opcode_stats)


# 3. Control Flow Graph using angr
def get_control_flow_graph(binary_path):
    print("CFG generation starts...")
    project = angr.Project(binary_path, auto_load_libs=False)

    # Perform CFG analysis using angr's CFGFast method
    cfg = project.analyses.CFGFast()

    # Create a directed graph for the control flow
    graph = nx.DiGraph()

    # Iterate over the nodes in the control flow graph
    for node in cfg.graph.nodes():
        graph.add_node(node.addr)  # Use the address as the node identifier

        # Iterate over the edges (successors) in the CFG
        for succ in cfg.graph.successors(node):
            graph.add_edge(
                node.addr, succ.addr
            )  # Add edges using the address of the nodes

    print("CFG generation ends...")
    return graph


# 4. File Relation Graph based on function calls (using r2pipe)
def get_file_relation_graph(binary_path):
    print("FRG generation starts...")
    r2 = r2pipe.open(binary_path)
    r2.cmd("aa")  # Analyze the binary
    functions = r2.cmd("afl").splitlines()  # Get all functions in the binary
    relation_graph = nx.Graph()

    for func in functions:
        func_addr = func.split()[0]  # Extract the function address
        xrefs = r2.cmd(f"axtj {func_addr}")  # Get cross-references for the function
        try:
            xrefs_data = json.loads(xrefs)  # Parse the cross-references to JSON

            # Iterate through cross-references and create edges for the relation graph
            for ref in xrefs_data:
                # Check for the expected keys in the cross-reference data
                if "to" in ref:
                    target = ref["to"]
                    relation_graph.add_edge(func_addr, target)
                else:
                    print(f"Warning: 'to' key missing in reference: {ref}")
        except json.JSONDecodeError:
            print(f"Error decoding JSON for xrefs: {xrefs}")
        except KeyError as e:
            print(f"KeyError: {e} in reference data: {xrefs}")

    print("FRG generation ends...")
    return relation_graph


# 5. Code Stylometry (analyze function names and mnemonics)
def get_code_stylometry(binary_path):
    print("Code Stylometry generation starts...")
    with open(binary_path, "rb") as f:
        binary_data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    mnemonics = []
    function_names = []

    for insn in md.disasm(binary_data, 0x1000):
        mnemonics.append(insn.mnemonic)

    # Use radare2 to get function names
    r2 = r2pipe.open(binary_path)
    functions = r2.cmd("afl").splitlines()
    for func in functions:
        function_names.append(func.split()[1])

    print("Code Stylometry generation ends...")
    return {"function_names": function_names, "mnemonics": mnemonics}


# Main analysis function to run all tasks
def analyze_binary(binary_path):
    results = {}

    results["decompiled_functions"] = get_decompiled_functions(binary_path)
    results["opcode_statistics"] = get_opcode_statistics(binary_path)
    results["control_flow_graph"] = get_control_flow_graph(binary_path)
    results["file_relation_graph"] = get_file_relation_graph(binary_path)
    results["code_stylometry"] = get_code_stylometry(binary_path)

    save_results(results)
    print("Results Saved")

    return results


binary_path = ""
analysis_results = analyze_binary(binary_path)
