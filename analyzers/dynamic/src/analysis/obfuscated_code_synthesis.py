import yara
import os
import hashlib
import requests
from io import BytesIO


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
    """
    match_details = []
    for match in matches:
        match_info = {
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": match.tags,
            "meta": match.meta,
            "strings": [
                {
                    "offset": offset,
                    "data": data.decode(errors="replace"),
                    "identifier": identifier,
                }
                for offset, identifier, data in match.strings
            ],
        }
        match_details.append(match_info)
    return match_details


def load_yara_rules_from_github(github_url):
    """
    Load YARA rules from a GitHub repository URL.
    """
    try:
        # Send a request to fetch the YARA rules from the GitHub URL
        response = requests.get(github_url)
        response.raise_for_status()  # Raise an exception if the HTTP request failed

        # Compile the YARA rules from the fetched content
        rules = yara.compile(fileobj=BytesIO(response.content))
        return rules
    except requests.exceptions.RequestException as e:
        print(f"Error downloading YARA rules: {e}")
        return None
    except yara.Error as e:
        print(f"Error compiling YARA rules: {e}")
        return None


def synthesize_semantics(file_path, github_yara_url):
    """
    Perform synthesis of semantics using YARA rules and extract detailed insights.
    """
    results = {"matches": [], "file_hashes": {}, "status": "pending"}
    try:
        # Step 1: Check if the file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Step 2: Compute file hashes for correlation
        results["file_hashes"] = compute_file_hashes(file_path)

        # Step 3: Load YARA rules from GitHub
        rules = load_yara_rules_from_github(github_yara_url)
        if not rules:
            raise FileNotFoundError(
                f"YARA rules file could not be loaded from GitHub: {github_yara_url}"
            )

        # Step 4: Match YARA rules against the file
        matches = rules.match(file_path)
        results["matches"] = extract_yara_match_details(matches)

        # Step 5: Update status
        results["status"] = "completed"
    except yara.Error as ye:
        results["error"] = f"YARA error: {str(ye)}"
        results["status"] = "failed"
    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"
    return results
