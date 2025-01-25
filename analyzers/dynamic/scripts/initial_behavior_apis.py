import r2pipe
import json
import networkx as nx


def api_initial_behavior(file_path):
    """
    Analyze APIs used in the initial behavior of the binary.
    This includes immediate calls as well as possible delayed execution indicators
    (e.g., time-based or file-based triggers) that might signal malicious behavior.
    """
    results = {
        "initial_apis": [],
        "delayed_behavior_indicators": [],
        "suspicious_patterns": [],
        "error": None,
        "status": None,
    }

    try:
        # Open the binary with r2pipe
        r2 = r2pipe.open(file_path)
        r2.cmd("aaa")  # Analyze the functions and references

        # Extract functions and potential initial API calls
        functions = r2.cmd("afl").splitlines()
        graph = nx.DiGraph()

        initial_apis = []  # Track immediate API calls
        delayed_indicators = []  # Track possible delayed behavior indicators
        suspicious_patterns = (
            []
        )  # Track suspicious patterns indicating malicious behavior

        # List of APIs that could be considered as "initial"
        initial_api_keywords = [
            "CreateFile",
            "RegOpenKey",
            "InternetOpen",
            "CreateProcess",
            "VirtualAlloc",
            "LoadLibrary",
            "WriteFile",
            "SetFilePointer",
            "SetEvent",
            "Sleep",
            "CreateThread",
            "OpenProcess",
            "NtCreateFile",
            "NtSetInformationFile",
        ]

        # Delayed behavior might be linked to these types of API calls
        delayed_api_keywords = [
            "Sleep",
            "CreateThread",
            "WaitForSingleObject",
            "SetTimer",
            "FindFirstFile",
            "GetTickCount",
            "GetLocalTime",
            "SetWaitableTimer",
        ]

        # Suspicious patterns indicative of malicious behavior
        suspicious_api_keywords = [
            "WriteProcessMemory",
            "ReadProcessMemory",
            "VirtualAllocEx",
            "CreateRemoteThread",
            "NtQuerySystemInformation",
            "RegSetValueEx",
            "InternetOpenUrlA",
            "CreateFileMapping",
        ]

        # Scan each function and check for API calls that may indicate initial or delayed behavior
        for func in functions:
            func_addr = func.split()[0]
            print(f"Processing function at address: {func_addr}")
            xrefs = r2.cmd(f"axtj {func_addr}")
            print(
                f"Cross-references for function {func_addr}: {xrefs}"
            )  # Debugging step
            try:
                xrefs_data = json.loads(xrefs)
                for ref in xrefs_data:
                    if "to" in ref:
                        target = ref["to"]
                        print(f"Found target API: {target}")  # Debugging step

                        # Check for immediate API calls based on initial API keywords
                        if any(keyword in target for keyword in initial_api_keywords):
                            initial_apis.append(target)

                        # Check for delayed behavior indicators
                        if any(keyword in target for keyword in delayed_api_keywords):
                            delayed_indicators.append(target)

                        # Check for suspicious patterns indicating malicious behavior
                        if any(
                            keyword in target for keyword in suspicious_api_keywords
                        ):
                            suspicious_patterns.append(target)

                        graph.add_edge(func_addr, target)

            except json.JSONDecodeError:
                print(f"Error decoding xrefs for function {func_addr}")
            except Exception as e:
                print(f"Error processing function {func_addr}: {str(e)}")

        # Update results with the initial and delayed behaviors
        results["initial_apis"] = initial_apis
        results["delayed_behavior_indicators"] = delayed_indicators
        results["suspicious_patterns"] = suspicious_patterns

        # Further analysis can be performed based on the collected initial and delayed indicators
        if len(initial_apis) > 0:
            print(f"Initial APIs found: {initial_apis}")
        else:
            print("No initial APIs found.")

        if len(delayed_indicators) > 0:
            print(f"Possible delayed behavior indicators: {delayed_indicators}")
        else:
            print("No delayed behavior indicators found.")

        if len(suspicious_patterns) > 0:
            print(f"Suspicious patterns found: {suspicious_patterns}")
        else:
            print("No suspicious patterns found.")

        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


def main():
    # Input binary path
    binary_file_path = "DroidCam.exe"  # Replace with your actual file path

    # Run the analysis
    results = api_initial_behavior(binary_file_path)

    # Print results summary
    if results["status"] == "completed":
        print(json.dumps(results, indent=4))
    else:
        print(f"An error occurred: {results['error']}")


if __name__ == "__main__":
    main()
