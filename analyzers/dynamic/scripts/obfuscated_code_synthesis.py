import yara
import os
import hashlib
import subprocess

repo_url = "https://github.com/Yara-Rules/rules.git"


def compute_file_hashes(file_path):
    """
    Compute MD5, SHA1, and SHA256 hashes for the given file.
    """
    hashes = {}
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["error"] = f"Failed to compute hashes: {str(e)}"
    return hashes


def extract_yara_match_details(matches):
    """
    Extract detailed information from YARA matches.
    Now we handle cases where matches might just be rule names.
    """
    match_details = []

    if isinstance(matches, list):  # Ensure we are processing a list of matches
        for match in matches:
            match_info = {
                "rule": match,  # Directly use the match as the rule name
                "namespace": "N/A",  # No namespace available
                "tags": [],  # Tags not available
                "meta": {},  # Meta not available
                "strings": [],  # No strings to process
            }
            match_details.append(match_info)
    else:
        # If a single match is returned
        match_details.append(
            {
                "rule": matches,  # Use the match as the rule name
                "namespace": "N/A",  # No namespace available
                "tags": [],
                "meta": {},
                "strings": [],
            }
        )

    return match_details


def clone_yara_rules_repository(repo_url, target_directory):
    """
    Clone the Yara-Rules GitHub repository if not already cloned.
    """
    try:
        if not os.path.exists(target_directory):
            subprocess.check_call(["git", "clone", repo_url, target_directory])
        else:
            subprocess.check_call(["git", "-C", target_directory, "pull"])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error cloning or updating repository: {e}")


def load_yara_rules_from_index(index_file):
    """
    Compile YARA rules from the index file.
    """
    try:
        rules = yara.compile(filepath=index_file)
        return rules
    except yara.Error as e:
        raise RuntimeError(f"Error compiling YARA rules: {e}")


def adjust_yara_include_paths(target_directory):
    """
    Fix or warn about missing include paths in YARA rules.
    """
    for root, _, files in os.walk(target_directory):
        for file in files:
            if file.endswith(".yar"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r") as yar_file:
                        lines = yar_file.readlines()

                    fixed_lines = []
                    for line in lines:
                        if line.strip().startswith("include"):
                            include_path = line.split('"')[1]
                            full_include_path = os.path.join(root, include_path)
                            if not os.path.exists(full_include_path):
                                print(
                                    f"Warning: Missing include file {include_path} in {file_path}"
                                )
                            fixed_lines.append(line)
                        else:
                            fixed_lines.append(line)

                    with open(file_path, "w") as yar_file:
                        yar_file.writelines(fixed_lines)

                except Exception as e:
                    print(f"Failed to process {file_path}: {e}")


def synthesize_semantics(file_path):
    """
    Perform synthesis of semantics using YARA rules and extract detailed insights.
    """
    results = {"matches": [], "file_hashes": {}, "status": "pending"}
    target_directory = "yara_rules"
    index_file = os.path.join(target_directory, "index.yar")

    adjust_yara_include_paths("yara_rules")

    try:
        # Step 1: Check if the file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Step 2: Compute file hashes for correlation
        results["file_hashes"] = compute_file_hashes(file_path)
        print(f"Computed file hashes: {results['file_hashes']}")

        # Step 3: Clone or update the YARA rules repository
        clone_yara_rules_repository(repo_url, target_directory)

        # Step 4: Load YARA rules from the index file
        if not os.path.isfile(index_file):
            raise FileNotFoundError(f"Index file not found: {index_file}")

        rules = load_yara_rules_from_index(index_file)

        # Step 5: Match YARA rules against the file
        matches = rules.match(file_path)

        # Ensure that matches are always in a list format (even if it's a single match)
        if isinstance(matches, yara.StringMatch):
            matches = [matches]  # Convert single match to a list
        elif not isinstance(matches, list):
            matches = (
                []
            )  # Ensure matches is an empty list if not a list or StringMatch object

        # Debug print for number of matches
        print(f"Total matches found: {len(matches)}")

        # Process matches with a limit
        if len(matches) > 50:
            print("Warning: Too many matches found. Limiting to the first 50.")

        # Step 6: Extract match details and update results
        results["matches"] = extract_yara_match_details(
            matches[:50]  # Limiting to first 50 matches
        )
        # print(results)
        # print(f"YARA matches: {results['matches']}")

        # Step 7: Update status
        results["status"] = "completed"

    except yara.Error as ye:
        results["error"] = f"YARA error: {str(ye)}"
        results["status"] = "failed"
    except FileNotFoundError as fnf:
        results["error"] = str(fnf)
        results["status"] = "failed"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


def obfuscated_code_synthesis(file_path):
    try:
        # Run the YARA analysis
        results = synthesize_semantics(file_path)
        return results
    except Exception as e:
        print(f"An error occurred during analysis: {e}")

