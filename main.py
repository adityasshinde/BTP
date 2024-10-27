import os
import sys
import random
from sandbox_config import create_sandbox
from analyzers.static_analyzer import run_static_analysis
from analyzers.dynamic_analyzer import run_dynamic_analysis

def main(file_path):
    print("[INFO] Starting malware analysis tool")

    # Create result directories
    #get a random 4 digit number
    id = random.randint(1000, 9999)
    os.makedirs("result"+str(id)+"/static", exist_ok=True)
    os.makedirs("result"+str(id)+"/dynamic", exist_ok=True)

    # Fix file path
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return

    # Step 1: Create sandbox and run the file in the sandbox
    sandbox_name = create_sandbox(file_path)

    # Step 2: Run static analysis
    static_report = run_static_analysis(file_path,output_path="result"+str(id)+"/static/static_report.json")
    
    # Step 3: Run dynamic analysis
    dynamic_report = run_dynamic_analysis(file_path, sandbox_name,output_path="result"+str(id)+"/dynamic/dynamic_report.json")

    print("[INFO] Malware analysis completed successfully")

if __name__ == "__main__":
    # Use raw string to avoid escape sequence warning
    exe_file_path = r"C:\Users\sadit\Downloads\wdksetup.exe"
    main(exe_file_path)