import re
import requests
import json


def downloader_graph_analysis(file_path):
    """
    Perform downloader graph analysis.
    This function scans the binary or logs for URLs and analyzes downloader behavior.
    """
    results = {"urls": [], "download_attempts": 0, "error": None, "status": None}

    try:
        # Extract URLs from the file
        extracted_urls = extract_urls(file_path)
        results["urls"] = extracted_urls
        results["download_attempts"] = len(extracted_urls)

        # Check if the URLs are known to be malicious using VirusTotal
        malicious_urls = check_urls_virustotal(extracted_urls)
        results["malicious_urls"] = malicious_urls

        # Set the status to completed after analysis
        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "failed"

    return results


def extract_urls(file_path):
    """
    Extract URLs from a file using regex.
    """
    url_pattern = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )

    extracted_urls = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                matches = url_pattern.findall(line)
                extracted_urls.update(matches)

        print(f"Extracted URLs: {list(extracted_urls)}")  # Print URLs for debugging

    except Exception as e:
        print(f"Error extracting URLs: {e}")

    return list(extracted_urls)


def check_urls_virustotal(urls):
    """
    Check URLs against VirusTotal API to determine if they are malicious.
    """
    VIRUS_TOTAL_API_KEY = "your_virustotal_api_key"  # Replace with your actual API key
    VIRUS_TOTAL_API_URL = "https://www.virustotal.com/api/v3/urls/"

    malicious_urls = []
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}

    for url in urls:
        try:
            # Send URL to VirusTotal for scanning
            response = requests.post(
                VIRUS_TOTAL_API_URL, headers=headers, data={"url": url}
            )
            response_json = response.json()

            # Extract the malicious verdict
            if response_json.get("data"):
                stats = response_json["data"]["attributes"]["last_analysis_stats"]
                if stats["malicious"] > 0 or stats["suspicious"] > 0:
                    malicious_urls.append(url)

        except requests.exceptions.RequestException as e:
            print(f"Error checking URL {url} on VirusTotal: {e}")

    return malicious_urls


def main():
    # Input binary or log file path
    file_path = "malware_logs.txt"  # Replace with actual file path

    # Perform downloader graph analysis
    results = downloader_graph_analysis(file_path)

    # Print results
    if results["status"] == "completed":
        print(json.dumps(results, indent=4))
    else:
        print(f"Error occurred: {results['error']}")


if __name__ == "__main__":
    main()
