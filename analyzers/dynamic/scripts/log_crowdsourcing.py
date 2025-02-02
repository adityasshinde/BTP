import os
import shutil
import time
import json
import requests
import re
import threading
import pandas as pd

# ---------------------- CONFIGURATION ----------------------

# Sandboxie-Plus logs directory (Change "Your_Sandbox_Name" to match your sandbox)
SANDBOX_PATH = r"C:\Sandbox\sadit\DefaultBox\user\current\AppData\Local\Temp"

# Local log file to monitor (Replace with your actual log file)
LOG_FILE_PATH = "log_monitor.txt"

# VirusTotal API Key (Replace with your API Key)
VIRUS_TOTAL_API_KEY = "key"
VIRUS_TOTAL_API_URL = "https://www.virustotal.com/api/v3/files"

# Suspicious logs storage
SUSPICIOUS_LOGS_FILE = "suspicious_logs.json"

# Sandbox extracted logs folder
EXTRACTED_LOGS_PATH = "sandbox_logs"

# Interval for checking logs (in seconds)
SCAN_INTERVAL = 30

# ---------------------- VIRUSTOTAL API ----------------------


def get_virus_total_score(file_path):
    """Uploads a file to VirusTotal and retrieves the analysis score."""
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(VIRUS_TOTAL_API_URL, headers=headers, files=files)
            response_json = response.json()

            if "data" in response_json:
                file_id = response_json["data"]["id"]
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
                analysis_response = requests.get(analysis_url, headers=headers).json()
                return analysis_response["data"]["attributes"]["stats"]["malicious"]
        return 0
    except requests.exceptions.RequestException as e:
        print(f"Error in VirusTotal lookup: {e}")
        return 0


# ---------------------- SUSPICIOUS ACTIVITY DETECTION ----------------------


def detect_suspicious_patterns(file_path):
    """Detects suspicious activity based on known indicators."""
    patterns = []
    if detect_registry_keys(file_path):
        patterns.append("SuspiciousRegistryKey")
    if detect_encrypted_config(file_path):
        patterns.append("EncryptedConfig")
    if detect_suspicious_file_access(file_path):
        patterns.append("SuspiciousFileAccess")
    return patterns


def detect_registry_keys(file_path):
    patterns = [
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
    ]
    return search_patterns_in_file(file_path, patterns)


def detect_encrypted_config(file_path):
    patterns = [r"^.{16,}$", r"\b[0-9a-fA-F]{32,}\b"]
    return search_patterns_in_file(file_path, patterns, binary=True)


def detect_suspicious_file_access(file_path):
    patterns = [
        r"C:\\Windows\\System32\\cmd\.exe",
        r"C:\\Windows\\Temp\\.*\.exe",
        r"C:\\Users\\.*\\AppData\\Local\\.*\.exe",
    ]
    return search_patterns_in_file(file_path, patterns)


def search_patterns_in_file(file_path, patterns, binary=False):
    """Scans logs for known suspicious patterns."""
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


# ---------------------- LOG MONITORING ----------------------


def extract_sandbox_logs():
    """Extract logs from Sandboxie and save them for analysis."""
    if not os.path.exists(EXTRACTED_LOGS_PATH):
        os.makedirs(EXTRACTED_LOGS_PATH)

    for filename in os.listdir(SANDBOX_PATH):
        file_path = os.path.join(SANDBOX_PATH, filename)
        if os.path.isfile(file_path):
            dest_path = os.path.join(EXTRACTED_LOGS_PATH, filename)
            shutil.copy(file_path, dest_path)
            print(f"[+] Extracted: {filename}")


def analyze_sandbox_logs():
    """Analyze logs extracted from the sandbox for suspicious activity."""
    if not os.path.exists(EXTRACTED_LOGS_PATH):
        return

    for filename in os.listdir(EXTRACTED_LOGS_PATH):
        file_path = os.path.join(EXTRACTED_LOGS_PATH, filename)
        suspicious_patterns = detect_suspicious_patterns(file_path)

        if suspicious_patterns:
            print(f"[!] Suspicious activity detected in {filename}")
            save_suspicious_logs({"file": filename, "patterns": suspicious_patterns})


def save_suspicious_logs(logs):
    """Save detected suspicious logs to a JSON file."""
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
    """Continuously monitors both system logs and sandbox logs."""
    print("[*] Starting log monitoring...")
    while True:
        # Monitor System Logs
        if os.path.exists(LOG_FILE_PATH):
            print("[*] Scanning logs...")
            suspicious_patterns = detect_suspicious_patterns(LOG_FILE_PATH)
            if suspicious_patterns:
                print("[!] Suspicious activity detected!")
                save_suspicious_logs(
                    {"file": LOG_FILE_PATH, "patterns": suspicious_patterns}
                )

        # Extract and analyze Sandboxie logs
        extract_sandbox_logs()
        analyze_sandbox_logs()

        time.sleep(SCAN_INTERVAL)


# ---------------------- PROC MONITORING ----------------------


def run_procmon():
    """Runs Process Monitor inside the sandbox to capture real-time logs."""
    PROC_MON_CMD = (
        'Start /wait "C:\\Program Files\\Procmon\\Procmon.exe" /AcceptEula /Quiet '
        '/Minimized /Backingfile "C:\\Sandbox\\Your_Sandbox_Name\\procmon_logs.PML"'
    )
    os.system(PROC_MON_CMD)


def convert_procmon_logs():
    """Convert Process Monitor logs to CSV."""
    PML_FILE = r"C:\Sandbox\Your_Sandbox_Name\procmon_logs.PML"
    CSV_FILE = "procmon_logs.csv"

    if os.path.exists(PML_FILE):
        os.system(
            f'"C:\\Program Files\\Procmon\\Procmon.exe" /OpenLog {PML_FILE} /SaveAs {CSV_FILE}'
        )
        print("[+] Procmon logs converted to CSV.")


def analyze_procmon_logs():
    """Analyzes the converted Process Monitor logs."""
    CSV_FILE = "procmon_logs.csv"
    if os.path.exists(CSV_FILE):
        df = pd.read_csv(CSV_FILE)
        print(df.head())  # Display the first few logs for analysis


# ---------------------- MAIN EXECUTION ----------------------


def start_background_monitor():
    """Starts all monitoring threads."""
    log_monitor_thread = threading.Thread(target=continuous_log_monitor, daemon=True)
    procmon_thread = threading.Thread(target=run_procmon, daemon=True)

    log_monitor_thread.start()
    procmon_thread.start()


def crowd_sourcing():
    start_background_monitor()
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Exiting log monitoring...")
        convert_procmon_logs()
        analyze_procmon_logs()

