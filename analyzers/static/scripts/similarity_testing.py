import r2pipe
import sys
import hashlib
import requests


def hash_code(binary_path):
    # Open the binary in radare2
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze all

    # Disassemble the first 1000 bytes to get a representative portion
    code = r2.cmd("pd 1000")

    # Create a hash of the disassembled code (e.g., SHA256)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    return code_hash


def compare_with_known_hashes(code_hash):
    # VirusTotal API URL for hash lookup
    api_url = f"https://www.virustotal.com/api/v3/files/{code_hash}"

    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
    apikey = ""
    with open("apikey.txt", "r") as file:
        apikey = file.read().strip()
    headers = {
        "x-apikey": apikey
    }

    try:
        # Send request to VirusTotal API to get information about the hash
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        # Parse the response JSON
        data = response.json()

        # Check if the hash is found in the VirusTotal database
        if "data" in data:
            malware_family = (
                data["data"]["attributes"]
                .get("popular_threat_classification", {})
                .get("suggested_threat_label", "Unknown Malware Family")
            )
            return f"Match found in VirusTotal: {malware_family}"
        else:
            return "No match found in VirusTotal database"
    except requests.exceptions.RequestException as e:
        # If API request fails, fall back to local hash database
        print(f"VirusTotal API request error: {e}. Falling back to local database.")

        # Local known hashes for fallback
        known_hashes = {
            "known_hash_1": "Malware Family A",
            "known_hash_2": "Malware Family B",
        }

        # Check if hash is in the local database
        match = known_hashes.get(code_hash, "No match found")
        return match


def main():
    if len(sys.argv) < 2:
        print("Usage: python similarity_testing.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    code_hash = hash_code(binary_path)
    match = compare_with_known_hashes(code_hash)

    print("Similarity Testing Result:")
    print(f"Code Hash: {code_hash}")
    print(f"Match: {match}")

    print("Termination: similarity_testing.py script completed successfully.")


if __name__ == "__main__":
    main()
