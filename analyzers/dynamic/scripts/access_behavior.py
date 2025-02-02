import os
import re
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# Setup logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Dynamic regex patterns for suspicious file paths
MALICIOUS_FILE_PATTERN = (
    r"(?i)(?:\b(keylogger|trojan|stealer|rat|botnet|payload|backdoor)\b|"  # Common malware names
    r"\\(AppData|Local|Roaming|Temp|SysWow64|System32|Startup|ProgramData)\\.*\.(exe|bat|dll|vbs|scr|ps1)$|"  # Suspicious folders + file extensions
    r"C:\\Users\\[^\\]+\\AppData\\.*\.(exe|bat|dll|vbs|scr|ps1)$)"  # Matches dynamic usernames
)

# Dynamic regex for suspicious registry keys
MALICIOUS_REGISTRY_PATTERN = (
    r"(?i)(?:\\(Run|RunOnce|Startup|AutoRun|Policies\\Explorer)\\|"  # Common persistence keys
    r"\\(CurrentVersion\\Run|Winlogon|Shell)\\)"
)


def is_suspicious_file(file_path: str) -> bool:
    """Determines if a file path is suspicious based on refined regex."""
    return bool(re.search(MALICIOUS_FILE_PATTERN, file_path))


def is_suspicious_registry(registry_key: str) -> bool:
    """Determines if a registry key is suspicious based on refined regex."""
    return bool(re.search(MALICIOUS_REGISTRY_PATTERN, registry_key))


def monitor_file_access(file_path: str):
    """Monitors file access and logs suspicious activity."""
    try:
        if is_suspicious_file(file_path):
            logging.warning(f"🚨 Suspicious file detected: {file_path}")
        else:
            logging.info(f"✅ File accessed: {file_path}")
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")


def monitor_registry_access(registry_key: str):
    """Monitors registry access and logs suspicious activity."""
    try:
        if is_suspicious_registry(registry_key):
            logging.warning(f"🚨 Suspicious registry detected: {registry_key}")
        else:
            logging.info(f"✅ Registry accessed: {registry_key}")
    except Exception as e:
        logging.error(f"Error processing registry {registry_key}: {e}")


def monitor_access_behavior(
    files: List[str], registry_keys: List[str]
) -> Dict[str, str]:
    """Monitors file and registry access concurrently using ThreadPoolExecutor."""
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(monitor_file_access, file) for file in files] + [
            executor.submit(monitor_registry_access, key) for key in registry_keys
        ]

        for future in futures:
            future.result()  # Wait for all tasks to complete

    return {"status": "completed"}


def access_behaviour(file_path):
    """Generalized main function that accepts command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Monitor files and registry keys for suspicious activity."
    )
    parser.add_argument(
        "--files", nargs="*", default=[], help="List of file paths to monitor."
    )
    parser.add_argument(
        "--registry", nargs="*", default=[], help="List of registry keys to monitor."
    )

    args = parser.parse_args()

    # Use provided input or fallback to defaults
    files_to_monitor = args.files or [
        os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"
        ),
        os.path.expandvars(r"%LOCALAPPDATA%\Temp\rat.exe"),
        os.path.expandvars(r"%WINDIR%\System32\malware.dll"),
        os.path.expandvars(r"%PROGRAMDATA%\App\update.bat"),
    ]

    registry_keys_to_monitor = args.registry or [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\hidden_payload",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\stealth_key",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\backdoor",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    ]

    logging.info(
        f"Starting monitoring for {len(files_to_monitor)} files and {len(registry_keys_to_monitor)} registry keys."
    )
    result = monitor_access_behavior(files_to_monitor, registry_keys_to_monitor)
    logging.info(f"Monitoring completed with status: {result['status']}")
