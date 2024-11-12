import os
import subprocess
import json
import sandboxie

# Sandboxie path for isolated execution
SANDBOX_PATH = r"C:\Program Files\Sandboxie-Plus\Start.exe"

# Script path to function mapping
ANALYSIS_FUNCTIONS = {
    "synthesis_of_semantics.py": "synthesize_semantics",
    "multi_hypothesis_testing.py": "run_multi_hypothesis_testing",
    "dfg_metrics_analysis.py": "analyze_dfg_metrics",
    "api_call_graph_analysis.py": "analyze_api_call_graph",
    "downloader_graph_analysis.py": "analyze_downloader_graph",
    "access_behavior_analysis.py": "analyze_access_behavior",
    "initial_api_behaviors.py": "analyze_initial_api_behaviors",
    "log_based_crowdsourcing.py": "analyze_log_based_crowdsourcing",
}

# Add this check in your code
def verify_python_installation():
    python_path = "C:\\Python312\\python.exe"
    if not os.path.exists(python_path):
        raise FileNotFoundError(
            f"Python not found at {python_path}. "
            "Please verify Python installation or update path."
        )

def verify_sandbox_access():
    if not os.path.exists(SANDBOX_PATH):
        raise FileNotFoundError(
            f"Sandboxie not found at {SANDBOX_PATH}. "
            "Please verify Sandboxie installation."
        )

def prepare_sandbox_command(sandbox_name, script_path, binary_path):
    # Verify all paths exist first
    python_path =r"C:\Python312\python.exe"
    
    # Convert all paths to absolute paths with proper escaping
    script_path = os.path.abspath(script_path)
    binary_path = os.path.abspath(binary_path)
    
    sandbox_cmd = [
        SANDBOX_PATH,
        "/wait",
        "/silent",
        python_path,
        script_path,
        binary_path
    ]
    
    # Verify paths exist before running
    if not os.path.exists(python_path):
        raise FileNotFoundError(f"Python executable not found at: {python_path}")
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Script not found at: {script_path}")
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found at: {binary_path}")
        
    return sandbox_cmd

def run_in_sandbox(sandbox_name, script_path, binary_path):
    try:
        # Verify requirements
        verify_python_installation()
        verify_sandbox_access()
        # Prepare command
        # sandbox_cmd = prepare_sandbox_command(sandbox_name, script_path, binary_path)
        sandbox_cmd= SANDBOX_PATH,"/wait","/silent",binary_path
        print(sandbox_cmd)
        # Print command for debugging
        print("Executing command:", " ".join(sandbox_cmd))
        
        # Execute command
        result = subprocess.run(
            sandbox_cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        return result.stdout
        
    except FileNotFoundError as e:
        print(f"Path error: {e}")
        raise
    except subprocess.CalledProcessError as e:
        print(f"Sandbox execution failed: {e}")
        print(f"Error output: {e.stderr}")
        raise

def run_dynamic_analysis(binary_path,sandbox_name, output_path):
    # Dictionary to store all results
    results = {}
    
    # Loop through and run each analysis script in Sandboxie
    for script_name in ANALYSIS_FUNCTIONS.keys():
        script_path = os.path.join(os.getcwd(),"analyzers","dynamic", "scripts", script_name)
        print(f"Running {script_name} analysis...")

        # Capture the output of each analysis script directly
        result = run_in_sandbox(sandbox_name,script_path, binary_path)
        
        # Store each script's output into combined results
        results[script_name] = result
    
    # Save all combined results to a single JSON file
    output_file = os.path.join(output_path)
    with open(output_file, "w") as json_file:
        json.dump(results, json_file, indent=4)

    print(f"Dynamic analysis complete. Combined results saved to {output_file}.")

