import requests
import time
import logging
import csv

# Configure logging to both console and a log file
log_filename = "scan_results.log"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.StreamHandler(),
    logging.FileHandler(log_filename)
])

def scan_file(api_key, hash_value, max_retries=3, timeout=10):
    """
    Scans the given hash using VirusTotal API and returns the results with the required attributes.

    :param api_key: The VirusTotal API key.
    :param hash_value: The hash to be scanned.
    :param max_retries: Maximum number of retries for transient errors.
    :param timeout: Timeout value for the API request in seconds.
    :return: A dictionary containing scan results and additional attributes.
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}

    # Try multiple attempts in case of transient issues
    for attempt in range(max_retries):
        try:
            # Make the API request with a timeout
            response = requests.get(url, headers=headers, timeout=timeout)

            # Check for successful response
            if response.status_code == 200:
                result = response.json()

                # Check if 'data' exists and is in the expected format
                data = result.get("data", {})
                if isinstance(data, dict):
                    attributes = data.get("attributes", {})

                    # Returning structured result with necessary attributes
                    return {
                        "scan_id": hash_value,
                        "magic": attributes.get("magic", "N/A"),
                        "tlsh": attributes.get("tlsh", "N/A"),
                        "type_tag": attributes.get("type_tag", "N/A"),
                        "md5": attributes.get("md5", "N/A"),
                        "sha256": attributes.get("sha256", "N/A"),
                        "authentihash": attributes.get("authentihash", "N/A"),
                        "dot_net_guids": attributes.get("dot_net_guids", "N/A"),
                        "file_type": attributes.get("type", "N/A"),
                        "probability": attributes.get("probability", "N/A"),
                        "scan_results": attributes.get("last_analysis_results", {}),
                        "permalink": result.get("links", {}).get("self", "N/A"),
                    }
                else:
                    # Log and return a default result for invalid data format
                    logging.error(f"Invalid data format for hash {hash_value}: {data}")
                    return create_error_response(hash_value, "Invalid data format from VirusTotal")
            elif response.status_code == 403:
                # Handle API key issues or permissions
                logging.error(f"Forbidden: API key may have expired or invalid permissions for hash {hash_value}")
                return create_error_response(hash_value, "API key issue (403 Forbidden)")
            elif response.status_code == 429:
                # Handle rate limiting, retry after a delay (Exponential Backoff)
                logging.warning(f"Rate limit exceeded, retrying... ({attempt + 1}/{max_retries})")
                time.sleep(2 ** attempt)  # Exponential backoff for retries
            else:
                # Handle other API errors
                logging.error(f"API Request failed for hash {hash_value} with status code {response.status_code}")
                return create_error_response(hash_value, f"API Request failed with status code {response.status_code}")

        except requests.exceptions.Timeout:
            # Handle request timeout
            logging.error(f"Timeout occurred while scanning {hash_value}")
            return create_error_response(hash_value, "Request Timeout")
        except requests.exceptions.RequestException as e:
            # Handle any general request exception
            logging.error(f"Request exception occurred while scanning {hash_value}: {e}")
            return create_error_response(hash_value, f"Request exception: {str(e)}")

    # After retries, if still unsuccessful, return failure
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

