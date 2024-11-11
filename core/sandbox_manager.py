import subprocess
import os
import time
import shutil

# Command to list all processes in the sandbox using Start.exe
def list_sandboxes_with_start(sbiectrl_exe, sandbox_name):
    try:
        # Use Start.exe to list all programs running in the given sandbox
        start_exe = os.path.join(sbiectrl_exe, "Start.exe")
        result = subprocess.run(
            [start_exe, f"/box:\"{sandbox_name}\"", "/listpids"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[INFO] List of processes running in sandbox '{sandbox_name}':\n{result.stdout}")
        else:
            print(f"[INFO] No processes found in sandbox '{sandbox_name}'.")
        return result.stdout
    except Exception as e:
        print(f"Error listing sandboxes with Start.exe: {e}")
        return None

def create_sandbox():
    sandbox_name = f"Malware Analysis"  # Using the desired sandbox name with spaces
    print(f"[INFO] Creating sandbox: {sandbox_name}")

    try:
        # Path to Sandboxie-Plus installation folder
        sandboxie_path = r"C:\Program Files\Sandboxie-Plus"
        sbiectrl_exe = os.path.join(sandboxie_path, "SbieCtrl.exe")

        # Check if Sandboxie executable exists
        if not os.path.exists(sbiectrl_exe):
            raise FileNotFoundError("Sandboxie-Plus SbieCtrl.exe not found")

        # Command to create the sandbox
        sandbox_command = f'"{sbiectrl_exe}" /box:create "{sandbox_name}"'
        
        # Run the command to create the sandbox
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

            # Wait for the sandbox to be fully created
            print("[INFO] Waiting for the sandbox to register...")
            time.sleep(5)  # Add a short delay to ensure the sandbox is registered

            # Now try listing processes in the sandbox
            # sandboxes = list_sandboxes_with_start(sandboxie_path, sandbox_name)
            # if sandboxes:
            #     print(f"[INFO] Sandboxes found:\n{sandboxes}")
            # else:
            #     print("[WARNING] No processes found in sandbox after creation.")
        else:
            print(f"[ERROR] Failed to create sandbox. Return code: {result.returncode}")
            print(f"[ERROR] Output: {result.stdout}")
            print(f"[ERROR] Error output: {result.stderr}")
            
    except FileNotFoundError as e:
        print(f"[ERROR] {str(e)}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Sandbox creation failed: {e}")
        print(f"[ERROR] Error output: {e.stderr}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")

    return sandbox_name

def move_to_sandbox(filepath):
    print("[INFO] Moving file to sandbox...")
    SANDBOX_PATH = "C:\\Sandbox\\sadit"
    SANDBOX_NAME = "Malware_Analysis"
    sandbox_filepath = os.path.join(SANDBOX_PATH, SANDBOX_NAME, "files", os.path.basename(filepath))
    print(sandbox_filepath)
    shutil.move(filepath, sandbox_filepath)
    return sandbox_filepath

def discard_file(filepath):
    print("[INFO] Discarding file...")
    os.remove(filepath)