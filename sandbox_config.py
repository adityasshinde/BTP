import subprocess
import uuid
import os

def create_sandbox(file_path):
    sandbox_name = f"Sandbox_{uuid.uuid4().hex[:8]}"
    print(f"[INFO] Creating sandbox: {sandbox_name}")

    try:
        sandboxie_path = r"C:\Program Files\Sandboxie-Plus\SbieCtrl.exe"
        
        if not os.path.exists(sandboxie_path):
            raise FileNotFoundError("Sandboxie-Plus SbieCtrl.exe not found")

        # Command to create the sandbox
        sandbox_command = f'"{sandboxie_path}" /create "{sandbox_name}"'
        
        # Run the command
        result = subprocess.run(
            sandbox_command,
            capture_output=True,
            text=True,
            check=True,
            shell=True
        )


        # Check if the sandbox was created successfully
        if result.returncode == 0:
            print(f"[INFO] Sandbox '{sandbox_name}' created successfully.")
            # Print the sandbox location
            sandbox_path = os.path.join("C:\\Sandbox", os.getlogin(), sandbox_name)
            print(f"[INFO] Sandbox location: {sandbox_path}")
        else:
            print(f"[ERROR] Failed to create sandbox. Return code: {result.returncode}")
            print(f"[ERROR] Output: {result.stdout}")
            print(f"[ERROR] Error output: {result.stderr}")

    except FileNotFoundError as e:
        print(f"[ERROR] {str(e)}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Sandbox execution failed: {e}")
        print(f"[ERROR] Error output: {e.stderr}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")

    return sandbox_name