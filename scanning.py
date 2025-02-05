import requests
import time
import logging
from queue import Queue

# Configure logging to both console and a log file
log_filename = "scan_results.log"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.StreamHandler(),
    logging.FileHandler(log_filename)
])

# Initialize a global log queue
log_queue = Queue()

def scan_file(api_key, hash_value, log_queue, max_retries=3, timeout=10):
    """
    Scans the given hash using the VirusTotal API and returns the results with the required attributes.

    :param api_key: The VirusTotal API key.
    :param hash_value: The hash to be scanned.
    :param log_queue: The log queue to store log entries.
    :param max_retries: Maximum number of retries for transient errors.
    :param timeout: Timeout value for the API request in seconds.
    :return: A dictionary containing scan results and additional attributes.
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)

            if "application/json" not in response.headers.get("Content-Type", ""):
                logging.error(f"Invalid content type for hash {hash_value}: {response.headers.get('Content-Type')}")
                return create_error_response(hash_value, "Invalid content type in response")

            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {})
                if isinstance(data, dict):
                    attributes = data.get("attributes", {})
                    scan_results = attributes.get("last_analysis_results", {})

                    # Extract the malicious, suspicious, and undetected values
                    malicious_count = sum(1 for engine in scan_results.values() if engine.get("category") == "malicious")
                    suspicious_count = sum(1 for engine in scan_results.values() if engine.get("category") == "suspicious")
                    undetected_count = sum(1 for engine in scan_results.values() if engine.get("category") == "undetected")

                    # Log entry with relevant attributes only (MD5, SHA256, malicious, suspicious, undetected)
                    log_entry = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "level": "INFO",
                        "message": "Scan completed.",
                        "vt_attributes": {
                            "md5": attributes.get("md5", "N/A"),
                            "sha256": attributes.get("sha256", "N/A"),
                            "malicious": malicious_count,
                            "suspicious": suspicious_count,
                            "undetected": undetected_count,
                        }
                    }

                    # Send the log entry to the log queue
                    log_queue.put(log_entry)

                    # Return the formatted scan results
                    return log_entry
                else:
                    logging.error(f"Invalid data format for hash {hash_value}: {data}")
                    return create_error_response(hash_value, "Invalid data format from VirusTotal")
            elif response.status_code == 404:
                logging.warning(f"No data found for hash {hash_value} (404 Not Found)")
                return create_error_response(hash_value, "No data found (404 Not Found)")
            elif response.status_code == 403:
                logging.error(f"Forbidden: API key issue for hash {hash_value}")
                return create_error_response(hash_value, "API key issue (403 Forbidden)")
            elif response.status_code == 429:
                logging.warning(f"Rate limit exceeded for hash {hash_value}, retrying... ({attempt + 1}/{max_retries})")
                time.sleep(2 ** attempt)
            else:
                logging.error(f"API Request failed for hash {hash_value} with status code {response.status_code}")
                return create_error_response(hash_value, f"API Request failed with status code {response.status_code}")

        except requests.exceptions.Timeout:
            logging.error(f"Timeout occurred while scanning {hash_value}")
            return create_error_response(hash_value, "Request Timeout")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request exception occurred while scanning {hash_value}: {e}")
            return create_error_response(hash_value, f"Request exception: {str(e)}")

    logging.error(f"Max retries reached for hash {hash_value}")
    return create_error_response(hash_value, "Max retries reached, request failed")


def create_error_response(hash_value, error_message):
    """
    Creates a structured error response.

    :param hash_value: The hash being scanned.
    :param error_message: The error message to be returned.
    :return: A dictionary containing the error response.
    """
    return {
        "scan_id": hash_value,
        "magic": "N/A",
        "tlsh": "N/A",
        "type_tag": "N/A",
        "md5": "N/A",
        "sha256": "N/A",
        "authentihash": "N/A",
        "dot_net_guids": "N/A",
        "file_type": "N/A",
        "probability": "N/A",
        "scan_results": {"error": f"{error_message} for hash: {hash_value}"},
        "permalink": "N/A"
    }
