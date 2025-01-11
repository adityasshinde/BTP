import os
import json
import subprocess


def run_script(script_name, binary_path, results_dict):
    try:
        # Run the script and capture its output
        result = subprocess.run(
            ["python", script_name, binary_path], capture_output=True, text=True
        )

        # Append the result (stdout) to the results dictionary
        results_dict[script_name] = result.stdout.strip()
        print(f"Successfully ran {script_name}")
    except Exception as e:
        print(f"Error while running {script_name}: {str(e)}")
        results_dict[script_name] = str(e)


def main():
    print("Starting malware analysis pipeline...\n")

    # Prompt user for binary path
    binary_path = os.path.join(os.getcwd(), "DroidCam.exe")

    # Validate the provided binary path
    if not os.path.isfile(binary_path):
        print(f"Error: File not found at {binary_path}")
        return

    print(f"Binary path provided: {binary_path}\n")

    # Define the result storage
    results = {}

    # List of scripts to run
    scripts = [
        "src/analysis/obfuscated_code_synthesis.py",
        "src/analysis/multi_hypothesis_testing.py",
        "src/analysis/dfg_metrics_analysis.py",
        "src/analysis/api_call_graph.py",
        "src/analysis/downloader_graph_analysis.py",
        "src/analysis/access_behavior.py",
        "src/analysis/initial_behavior_apis.py",
        "src/analysis/log_crowdsourcing.py",
    ]

    # Run all scripts and capture the output
    for script in scripts:
        run_script(script, binary_path, results)

    # Save all results to a JSON file
    results_file = os.path.join(os.getcwd(), "results", "analysis_results.json")
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, "w") as json_file:
        json.dump(results, json_file, indent=4)

    print("\nMalware analysis pipeline completed.")
    print(f"Results saved to {results_file}")


if __name__ == "__main__":
    main()
