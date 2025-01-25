import json
import requests
import re
import base64
import threading
import time
import os

# Set your VirusTotal API key here
VIRUS_TOTAL_API_KEY = "your_api_key"  # Replace with actual API key
VIRUS_TOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

# File path for logs (Replace with actual path)
LOG_FILE_PATH = "malware_logs.txt"  # File containing logs to monitor

# Interval in seconds to check logs
SCAN_INTERVAL = 30  # Adjust as needed

# Path to store collected suspicious logs
SUSPICIOUS_LOGS_FILE = "suspicious_logs.json"


def log_based_crowdsourcing(file_path):
    """
    Perform log-based crowdsourcing analysis.
    This will query VirusTotal and analyze known indicators in logs.
    """
    results = {
        "virus_total_score": None,
        "known_indicators": [],
        "suspicious_patterns": [],
        "error": None,
        "status": None,
    }

    try:
        virus_total_score = get_virus_total_score(file_path)
        results["virus_total_score"] = virus_total_score

        known_indicators = [
            "SuspiciousRegistryKey",
            "EncryptedConfig",
            "SuspiciousFileAccess",
        ]
        results["known_indicators"] = detect_known_indicators(
            file_path, known_indicators
        )
        results["suspicious_patterns"] = detect_suspicious_patterns(file_path)
        results["status"] = "completed"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


def get_virus_total_score(file_path):
    """
    Get the file score from VirusTotal using its API.
    """
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            file_base64 = base64.b64encode(file_data).decode()

        headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
        url = f"{VIRUS_TOTAL_API_URL}{file_base64}"
        response = requests.get(url, headers=headers)
        response_json = response.json()

        virus_score = response_json["data"]["attributes"]["last_analysis_stats"][
            "malicious"
        ]
        return virus_score
    except requests.exceptions.RequestException as e:
        print(f"Error in VirusTotal lookup: {e}")
        return 0


def detect_known_indicators(file_path, indicators):
    # Dictionary mapping indicators to their corresponding detection functions
    detection_functions = {
        "SuspiciousRegistryKey": detect_registry_keys,
        "EncryptedConfig": detect_encrypted_config,
        "SuspiciousFileAccess": detect_suspicious_file_access,
    }

    detected_indicators = []

    # Ensure the file path is valid before proceeding
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file at {file_path} does not exist.")

    # Iterate through indicators and call corresponding detection function
    for indicator in indicators:
        # Check if the indicator is known and call the respective detection function
        if indicator in detection_functions:
            if detection_functions[indicator](
                file_path
            ):  # Call the corresponding detection function
                detected_indicators.append(indicator)

    return detected_indicators


def detect_registry_keys(file_path):
    patterns = [
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*",
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*",
    ]
    return search_patterns_in_file(file_path, patterns)


def detect_encrypted_config(file_path):
    patterns = [r"^.{16,}$", r"\b[0-9a-fA-F]{32,}\b"]
    return search_patterns_in_file(file_path, patterns, binary=True)


def detect_suspicious_file_access(file_path):
    # Patterns for suspicious file access
    patterns = [
        # Looks for command prompt (cmd.exe) usage in System32
        r"C:\\Windows\\System32\\cmd\.exe",
        # Looks for suspicious executables in temp directories or other sensitive paths
        r"C:\\Windows\\Temp\\.*\.exe",  # Looking for any executable in temp directory, not just specific names
        # Looking for suspicious files in common paths (can add more patterns as needed)
        r"C:\\Users\\.*\\AppData\\Local\\.*\.exe",  # Executables in user AppData folders
        r"C:\\Program Files\\.*\\.*\.exe",  # Any executable in Program Files
    ]

    return search_patterns_in_file(file_path, patterns)


def search_patterns_in_file(file_path, patterns, binary=False):
    try:
        mode = "rb" if binary else "r"
        encoding = None if binary else "utf-8"
        with open(file_path, mode, encoding=encoding, errors="ignore") as f:
            file_content = f.read()
            for pattern in patterns:
                if re.search(pattern.encode() if binary else pattern, file_content):
                    return True
    except Exception as e:
        print(f"Error searching patterns: {e}")
    return False


def detect_suspicious_patterns(file_path):
    patterns = []
    if detect_registry_keys(file_path):
        patterns.append("SuspiciousRegistryKey")
    if detect_encrypted_config(file_path):
        patterns.append("EncryptedConfig")
    if detect_suspicious_file_access(file_path):
        patterns.append("SuspiciousFileAccess")
    return patterns


def save_suspicious_logs(logs):
    try:
        if os.path.exists(SUSPICIOUS_LOGS_FILE):
            with open(SUSPICIOUS_LOGS_FILE, "r", encoding="utf-8") as f:
                existing_logs = json.load(f)
        else:
            existing_logs = []
        existing_logs.append(logs)
        with open(SUSPICIOUS_LOGS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_logs, f, indent=4)
        print("[+] Suspicious logs saved!")
    except Exception as e:
        print(f"Error saving logs: {e}")


def continuous_log_monitor():
    print("[*] Background log monitoring started...")
    print(f"[*] Checking for log file at: {os.path.abspath(LOG_FILE_PATH)}")
    time.sleep(5)  # Allow time for log generation

    # Check if the log file exists, if not create one with a default name "malicious_file.log"
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[!] Log file not found: {LOG_FILE_PATH}")
        create_malicious_file(LOG_FILE_PATH)

    while True:
        if os.path.exists(LOG_FILE_PATH):
            print("[*] Scanning logs...")
            results = log_based_crowdsourcing(LOG_FILE_PATH)
            if results["status"] == "completed":
                if results["suspicious_patterns"] or results["known_indicators"]:
                    print("[!] Suspicious activity detected!")
                    save_suspicious_logs(results)
        else:
            print(f"[!] Log file not found: {LOG_FILE_PATH}")
            create_malicious_file(LOG_FILE_PATH)

        time.sleep(SCAN_INTERVAL)


def create_malicious_file(file_path):
    """
    Generate a malicious file if it doesn't exist.
    """
    try:
        print(f"[+] Creating malicious file: {file_path}")
        malicious_content = "This is a placeholder for a malicious log file.\nSuspicious activity detected!"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(malicious_content)
        print(f"[+] Malicious file created at: {file_path}")
    except Exception as e:
        print(f"[!] Error creating malicious file: {e}")


def start_background_monitor():
    monitor_thread = threading.Thread(target=continuous_log_monitor, daemon=True)
    monitor_thread.start()


if __name__ == "__main__":
    start_background_monitor()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting log monitoring...")
