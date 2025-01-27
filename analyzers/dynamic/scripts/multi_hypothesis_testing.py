import pefile
import math
import string
import re


def calculate_entropy(data):
    """
    Calculate Shannon entropy to detect packed or encrypted sections.
    """
    if not data:
        return 0
    entropy = 0
    data_size = len(data)
    frequency = {byte: data.count(byte) for byte in set(data)}

    for count in frequency.values():
        probability = count / data_size
        entropy -= probability * math.log2(probability)

    return entropy


def detect_packing(pe):
    """
    Detect if the binary might be packed or obfuscated.
    """
    packed_sections = {}
    for section in pe.sections:
        entropy = calculate_entropy(section.get_data())
        if entropy > 7.5:  # High entropy suggests packing or encryption
            packed_sections[section.Name.decode().strip("\x00")] = entropy

    return packed_sections


def extract_imports(pe):
    """
    Extract imported API functions from the binary.
    """
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())
    return imports


def scan_strings(file_path):
    """
    Extract ASCII and Unicode strings to detect suspicious patterns.
    """
    with open(file_path, "rb") as f:
        data = f.read()

    # ASCII Strings
    ascii_strings = re.findall(rb"[ -~]{4,}", data)

    # Unicode Strings
    unicode_strings = re.findall(rb"(?:[\x20-\x7E][\x00]){4,}", data)

    suspicious_patterns = [
        b"cmd.exe",
        b"powershell",
        b"system(",
        b"eval(",
        b"base64,",
        b"HTTP",
        b"/bin/sh",
        b"shellcode",
        b"keylogger",
        b"reverse_tcp",
        b"nc -e",
        b"b64decode",
    ]

    detected_strings = {
        "ascii": [
            s.decode(errors="ignore")
            for s in ascii_strings
            if any(p in s for p in suspicious_patterns)
        ],
        "unicode": [
            s.decode("utf-16", errors="ignore")
            for s in unicode_strings
            if any(p in s for p in suspicious_patterns)
        ],
    }

    return detected_strings


def check_code_injection_apis(api_list):
    """
    Identify APIs commonly used in code injection and process hollowing.
    """
    injection_apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetThreadContext",
        "QueueUserAPC",
        "LoadLibraryA",
        "GetProcAddress",
        "RtlCreateUserThread",
    ]
    return [api for api in injection_apis if api in api_list]


def check_persistence_mechanisms(api_list):
    """
    Detect persistence mechanisms via suspicious API calls.
    """
    persistence_apis = [
        "RegCreateKeyExA",
        "RegSetValueExA",
        "CreateServiceA",
        "ChangeServiceConfigA",
        "WriteFile",
        "ShellExecuteA",
        "WinExec",
        "SetWindowsHookExA",
        "AddFontResourceA",
    ]
    return [api for api in persistence_apis if api in api_list]


def check_pe_anomalies(pe):
    """
    Detect anomalies in PE headers (e.g., oversized sections, missing data directories).
    """
    anomalies = []

    # Check if NumberOfSections is unusually high
    if pe.FILE_HEADER.NumberOfSections > 10:
        anomalies.append(
            f"Unusually high number of sections: {pe.FILE_HEADER.NumberOfSections}"
        )

    # Check for oversized sections
    for section in pe.sections:
        if section.SizeOfRawData > 10 * 1024 * 1024:  # 10MB limit
            anomalies.append(
                f"Oversized section detected: {section.Name.decode().strip()}"
            )

    return anomalies


def multi_hypothesis_testing(file_path):
    """
    Perform multi-hypothesis testing for malware analysis.
    """
    results = {
        "encryption_detected": False,
        "suspicious_apis": [],
        "packed_sections": {},
        "entropy_analysis": {},
        "code_injection_apis": [],
        "persistence_apis": [],
        "suspicious_strings": {},
        "pe_anomalies": [],
        "status": "pending",
    }

    try:
        pe = pefile.PE(file_path)

        # Hypothesis 1: Check for packed or encrypted code
        packed_sections = detect_packing(pe)
        if packed_sections:
            results["encryption_detected"] = True
            results["packed_sections"] = packed_sections

        # Hypothesis 2: Extract and analyze imported APIs
        imports = extract_imports(pe)
        results["suspicious_apis"] = check_code_injection_apis(
            imports
        ) + check_persistence_mechanisms(imports)
        results["code_injection_apis"] = check_code_injection_apis(imports)
        results["persistence_apis"] = check_persistence_mechanisms(imports)

        # Hypothesis 3: Perform entropy analysis on PE sections
        entropy_values = {
            section.Name.decode().strip("\x00"): calculate_entropy(section.get_data())
            for section in pe.sections
        }
        results["entropy_analysis"] = entropy_values

        # Hypothesis 4: Scan for suspicious strings
        results["suspicious_strings"] = scan_strings(file_path)

        # Hypothesis 5: Check PE structure for anomalies
        results["pe_anomalies"] = check_pe_anomalies(pe)

        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


# Example usage
binary_path = "DroidCam.exe"
analysis_results = multi_hypothesis_testing(binary_path)
print(analysis_results)
