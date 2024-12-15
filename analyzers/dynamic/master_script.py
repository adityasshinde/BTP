from src.analysis.obfuscated_code_synthesis import synthesize_semantics
from src.analysis.multi_hypothesis_testing import multi_hypothesis_testing
from src.analysis.dfg_metrics_analysis import analyze_dfg_metrics
from src.analysis.api_call_graph import simplified_api_call_graph
from src.analysis.downloader_graph_analysis import downloader_graph_analysis
from src.analysis.access_behavior import monitor_access_behavior
from src.analysis.initial_behavior_apis import api_initial_behavior
from src.analysis.log_crowdsourcing import log_based_crowdsourcing
import os


def main():
    print("Starting malware analysis pipeline...\n")

    # Prompt user for binary path
    binary_path = input("Enter the path to the binary file for analysis: ").strip()

    # Validate the provided binary path
    if not os.path.isfile(binary_path):
        print(f"Error: File not found at {binary_path}")
        return

    print(f"Binary path provided: {binary_path}\n")

    # Provide the binary path to the relevant function
    synthesize_semantics(binary_path)
    multi_hypothesis_testing({"hypothesis1": [0.4, 0.5, 0.6]})
    analyze_dfg_metrics({"nodes": [1, 2, 3], "edges": [(1, 2), (2, 3)]})
    simplified_api_call_graph(
        {"nodes": ["A", "B", "A"], "edges": [("A", "B"), ("B", "A")]}
    )
    downloader_graph_analysis({"nodes": ["clean_node", "suspicious_node"], "edges": []})
    monitor_access_behavior([{"status": "failed"}, {"status": "success"}])
    api_initial_behavior(["critical_function", "non_critical_function"])
    log_based_crowdsourcing([{"id": 1, "votes": 10}, {"id": 2, "votes": 5}])

    print("\nMalware analysis pipeline completed.")


if __name__ == "__main__":
    main()
