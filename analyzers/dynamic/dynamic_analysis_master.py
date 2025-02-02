import os
import json
import threading
from analyzers.dynamic.scripts.obfuscated_code_synthesis import obfuscated_code_synthesis
from analyzers.dynamic.scripts.multi_hypothesis_testing import multi_hypothesis_testing
from analyzers.dynamic.scripts.dfg_metrics_analysis import analyze_dfg_metrics
from analyzers.dynamic.scripts.api_call_graph import detailed_api_call_graph
from analyzers.dynamic.scripts.downloader_graph_analysis import downloader_graph_analysis
from analyzers.dynamic.scripts.access_behavior import access_behaviour
from analyzers.dynamic.scripts.initial_behavior_apis import api_initial_behavior
from analyzers.dynamic.scripts.log_crowdsourcing import crowd_sourcing

# Mapping of script paths to their corresponding functions
SCRIPT_FUNCTIONS = {
    "scripts/obfuscated_code_synthesis.py": obfuscated_code_synthesis,
    "scripts/multi_hypothesis_testing.py": multi_hypothesis_testing,
    "scripts/dfg_metrics_analysis.py": analyze_dfg_metrics,
    "scripts/api_call_graph.py": detailed_api_call_graph,
    "scripts/initial_behavior_apis.py": api_initial_behavior,
    "scripts/downloader_graph_analysis.py": downloader_graph_analysis,
    "scripts/access_behavior.py": access_behaviour,
}

def run_script(script_name, binary_path, results_dict):
    try:
        func = SCRIPT_FUNCTIONS.get(script_name)
        if func:
            result = func(binary_path)
            results_dict[script_name] = result if result else "Success"
            print(f"Successfully ran {script_name}")
        else:
            raise ValueError(f"No function mapped for {script_name}")
    except Exception as e:
        print(f"Error while running {script_name}: {str(e)}")
        results_dict[script_name] = str(e)

def run_other_scripts(binary_path, results_dict):
    for script in SCRIPT_FUNCTIONS.keys():
        run_script(script, binary_path, results_dict)

def run_dynamic_analysis(binary_path, output_path):
    results = {}
    
    # Create a thread for running crowd_sourcing
    crowd_thread = threading.Thread(target=lambda: results.update({"crowd_sourcing": crowd_sourcing()}))
    
    # Create a thread for running all other scripts
    scripts_thread = threading.Thread(target=run_other_scripts, args=(binary_path, results))
    
    # Start both threads
    crowd_thread.start()
    scripts_thread.start()
    
    # Wait for scripts_thread to complete first
    scripts_thread.join()
    
    # Stop crowd_thread after scripts_thread is done
    if crowd_thread.is_alive():
        print("Terminating crowd_sourcing thread")
        del crowd_thread
    
    # Save all results to a JSON file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as json_file:
        json.dump(results, json_file, indent=4)
    
    print(f"Analysis complete. Results saved to {output_path}")
