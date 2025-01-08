# VT Hash Scanner Tool

## Overview

The VT Hash Scanner Tool is a Python-based utility that scans files using the VirusTotal API. It allows users to upload hash values (MD5, SHA256, etc.) to VirusTotal, check their status, and retrieve analysis results from various antivirus engines. The tool also provides an option to export the results into a CSV file for easier analysis.

## Features

- Scan hash values (MD5, SHA256, etc.) using the VirusTotal API.
- Retrieve detailed analysis results, including engine names and verdicts.
- Export scan results to CSV for further analysis.
- Supports retries in case of transient API errors.
- Provides a simple interface to interact with the tool.

## Installation

To run the VT Hash Scanner Tool, follow these steps:

### Prerequisites

Ensure that you have Python 3.6 or higher installed on your system.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bakhtiyarjatoi/vt-hash-scanner.git
   cd vt-hash-scanner
   ```

2. **Install dependencies**:
   You can use `pip` to install the required dependencies.
   ```bash
   pip install -r requirements.txt
   ```

### VirusTotal API Key

To use the tool, you need a valid VirusTotal API key. Follow these steps to obtain one:

1. Go to [VirusTotal API](https://www.virustotal.com/gui/home/upload).
2. Sign up or log in to your account.
3. Go to your [API key page](https://www.virustotal.com/ui/user/settings).
4. Copy the API key.

Once you have the API key, you can input it when prompted by the tool.

## Usage

1. Run the script:
   ```bash
   python vt_hash_scanner.py
   ```

2. Enter the hash value (MD5, SHA256, or other supported formats) you want to scan.
3. The tool will retrieve results from VirusTotal and display them on the screen.
4. Optionally, you can export the results to a CSV file.

### Example

```bash
Enter the hash to scan: 098f6bcd4621d373cade4e832627b4f6
Scanning hash... Please wait...
Scan results for hash 098f6bcd4621d373cade4e832627b4f6:
- MD5: 098f6bcd4621d373cade4e832627b4f6
- SHA256: 8c56a39dfcf440e60e25876ab7648f0f...
- Scan Results: Engine A: Clean, Engine B: Infected, Engine C: Suspicious
```

## Exporting Results

You can export the scan results to a CSV file by selecting the "Export" option. The following columns are included in the exported CSV file:

- Hash
- Magic
- TLSH
- Type Tag
- MD5
- SHA256
- Authentihash
- .NET GUIDs
- File Type
- Probability
- Scan Results
- VT Link

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or issues, feel free to reach out to the project maintainer:

- Name: [Bakhtiyar Ahmad]
- GitHub: [https://github.com/bakhtiyarjatoi](https://github.com/bakhtiyarjatoi)

```

### Key Sections in the README:
- **Overview**: A brief description of the tool and its functionalities.
- **Features**: A bullet-point list of key features of the tool.
- **Installation**: Step-by-step instructions on how to install the tool and its dependencies.
- **VirusTotal API Key**: Instructions on obtaining and using the API key.
- **Usage**: How to run the tool, provide input, and view results.
- **Exporting Results**: Instructions on how to export scan results.
- **License**: A standard section indicating the project’s license (MIT in this case).
- **Contact**: A place for providing your contact information for support.
