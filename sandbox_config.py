import subprocess
import uuid
import os
import time

def create_sandbox(file_path):
    sandbox_name = f"Sandbox_{uuid.uuid4().hex[:8]}"
    print(f"[INFO] Creating sandbox: {sandbox_name}")

    try:
        sandboxie_path = r"C:\Program Files\Sandboxie-Plus\Start.exe"
        if not os.path.exists(sandboxie_path):
            raise FileNotFoundError("Sandboxie-Plus Start.exe not found")

        sandbox_command = [
            sandboxie_path,
            f"/box:{sandbox_name}",
            "/wait",  # Wait for process completion
            file_path
        ]
        
        result = subprocess.run(
            sandbox_command,
            capture_output=True,
            text=True,
            check=True
        )
        
        print(f"[INFO] Executed {file_path} in sandbox: {sandbox_name}")
        print(f"[INFO] Sandbox output: {result.stdout}")
        
    except FileNotFoundError as e:
        print(f"[ERROR] {str(e)}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Sandbox execution failed: {e}")
        print(f"[ERROR] Error output: {e.stderr}")

    return sandbox_name