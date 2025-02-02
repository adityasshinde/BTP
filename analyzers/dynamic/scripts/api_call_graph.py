import r2pipe
import json
import networkx as nx


def detailed_api_call_graph(file_path):
    """
    Create a comprehensive Data Dependent API Call Graph.
    This function extracts API calls, arguments, and builds a detailed call graph with
    data dependencies and interactions between the APIs in a binary.
    """
    results = {
        "nodes": [],
        "edges": [],
        "api_calls": [],
        "data_dependencies": [],
        "error": None,
        "frequent_api_calls": {},
    }

    try:
        # Open the binary with r2pipe
        print("Opening binary...")
        r2 = r2pipe.open(file_path)
        r2.cmd("aaa")  # Analyze all functions and code references
        functions = r2.cmd("afl").splitlines()  # List of all functions

        # Check if functions were retrieved
        print(f"Functions found: {len(functions)}")
        if len(functions) == 0:
            raise ValueError("No functions found in the binary.")

        # Initialize the graph
        graph = nx.DiGraph()  # Directed graph to represent API call relations

        # Placeholder for API calls and data dependencies
        api_calls = []
        data_dependencies = []

        # Iterate through each function to find API calls
        for func in functions:
            func_addr = func.split()[0]
            print(f"Processing function at address: {func_addr}")
            xrefs = r2.cmd(
                f"axtj {func_addr}"
            )  # Cross-references for the function (API calls)

            # Debugging: print xrefs data for the function
            print(f"Cross-references for {func_addr}: {xrefs}")

            try:
                xrefs_data = json.loads(xrefs)

                for ref in xrefs_data:
                    if "to" in ref:
                        target = ref["to"]
                        api_call_details = {"from": func_addr, "to": target}

                        # Extract arguments if available
                        args = r2.cmd(f"pd {func_addr}")  # Disassemble the function
                        api_call_details["arguments"] = args.splitlines()

                        # Add to the graph and store API call details
                        api_calls.append(api_call_details)
                        graph.add_edge(func_addr, target)  # Create edge in the graph

                    if "data" in ref:
                        # Track data flow dependencies
                        data_dependencies.append(
                            {"source": ref.get("from"), "target": ref.get("to")}
                        )

            except json.JSONDecodeError:
                print(f"Error decoding xrefs for function {func_addr}")
            except Exception as e:
                print(f"Error processing function {func_addr}: {str(e)}")

        # Check if any API calls were found
        if len(api_calls) == 0:
            raise ValueError("No API calls found in the binary.")

        # Extract nodes and edges from the graph
        results["nodes"] = list(graph.nodes)
        results["edges"] = [f"{u} -> {v}" for u, v in graph.edges]

        # Capture the API calls and data dependencies
        results["api_calls"] = api_calls
        results["data_dependencies"] = data_dependencies

        # Perform basic call graph analysis
        # Identify most frequently called APIs
        api_call_freq = {}
        for call in api_calls:
            target = call["to"]
            api_call_freq[target] = api_call_freq.get(target, 0) + 1

        # Add the most frequently called APIs to the results
        results["frequent_api_calls"] = {
            k: v
            for k, v in sorted(
                api_call_freq.items(), key=lambda item: item[1], reverse=True
            )[:10]
        }

        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results

