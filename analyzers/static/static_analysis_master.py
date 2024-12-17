import os
import json
from analyzers.static.scripts.binary_features import extract_binary_features
from analyzers.static.scripts.disassemble import disassemble
from analyzers.static.scripts.extract_functions import extract_function_names
from analyzers.static.scripts.similarity_testing import similarity_test
from analyzers.static.scripts.register_analysis import analyze_registers
from analyzers.static.scripts.subroutine_detection import detect_subroutines
from analyzers.static.scripts.statistics import collect_statistics
from analyzers.static.scripts.file_relations import analyze_file_relations
from analyzers.static.scripts.stylometry import analyze_stylometry

# Mapping of script paths to their corresponding functions
SCRIPT_FUNCTIONS = {
    "scripts/disassemble.py": disassemble, #reverse engineering
    "scripts/extract_functions.py": extract_function_names,#reverse engineering
    "scripts/similarity_testing.py": similarity_test, #static analysis
    "scripts/register_analysis.py": analyze_registers, #static analysis
    "scripts/binary_features.py": extract_binary_features,#reverse engineering
    "scripts/subroutine_detection.py": detect_subroutines, #static analysis
    "scripts/statistics.py": collect_statistics,#reverse engineering
    "scripts/file_relations.py": analyze_file_relations,#analysis
    "scripts/stylometry.py": analyze_stylometry,#analysis
}

def run_script(script_name, binary_path, results_dict):
    try:
        # Get the function associated with the script name
        func = SCRIPT_FUNCTIONS.get(script_name)
        
        if func:
            # Run the function and capture the result
            result = func(binary_path)
            # Append the result to the results dictionary
            results_dict[script_name] = result if result else "Success"
            print(f"Successfully ran {script_name}")
        else:
            raise ValueError(f"No function mapped for {script_name}")
            
    except Exception as e:
        print(f"Error while running {script_name}: {str(e)}")
        results_dict[script_name] = str(e)

def run_static_analysis(binary_path, output_path):
    results = {}
    
    # List of script paths to run
    scripts = list(SCRIPT_FUNCTIONS.keys())
    
    for script in scripts:
        run_script(script, binary_path, results)

    # Save all results to a JSON file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as json_file:
        json.dump(results, json_file, indent=4)

    print(f"Analysis complete. Results saved to {output_path}")
