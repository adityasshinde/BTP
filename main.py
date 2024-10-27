import os
import sys
from sandbox_config import create_sandbox
from analyzers.static_analyzer import run_static_analysis
from analyzers.dynamic_analyzer import run_dynamic_analysis

def main(file_path):
    print("[INFO] Starting malware analysis tool")

    # Create result directories
    os.makedirs("result/static", exist_ok=True)
    os.makedirs("result/dynamic", exist_ok=True)

    # Fix file path
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return

    # Step 1: Create sandbox and run the file in the sandbox
    sandbox_name = create_sandbox(file_path)

    # Step 2: Run static analysis
    static_report = run_static_analysis(file_path)
    
    # Step 3: Run dynamic analysis
    dynamic_report = run_dynamic_analysis(file_path)

    print("[INFO] Malware analysis completed successfully")

if __name__ == "__main__":
    # Use raw string to avoid escape sequence warning
    exe_file_path = r"C:\Program Files\Sandboxie-Plus\api-monitor-v2r13-setup-x86.exe"
    main(exe_file_path)