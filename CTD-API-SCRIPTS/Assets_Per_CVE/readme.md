# Assets Per CVE Exporter

This script connects to a Claroty CTD instance, authenticates, and retrieves a comprehensive mapping of confirmed CVEs and the specific assets they affect. It features an interactive command-line interface that allows you to filter your queries and customize the exported data.

## Features

*   **CVE Filtering:** Pull data for all vulnerabilities in the environment, or filter for a single specific CVE ID.
*   **Time Windows:** Optionally filter the results by a specific detection timeframe (Start/End Dates).
*   **Custom Field Selection:** Dynamically append additional asset details to your report (e.g., `ipv4`, `mac`, `vendor`, `os`, `firmware`).
*   **Flexible Output:** Export your findings into either two related CSV files or a single nested JSON file.
*   **`Assets_Per_CVE_PS.ps1`**: same script, runnable through powershell. 


## Prerequisites

Ensure you have Python 3 installed along with the `requests` library. You can install the required dependencies in the `requirements.txt` file in the root directory, or by using:

```bash
pip install requests urllib3
```

## Usage
Navigate to the directory the script lives in and run the script from your terminal:

```bash
python Assets_Per_CVEv3.py
```

Upon running, you will be prompted to enter:
1. Your CTD IP/Hostname and credentials.
2. An optional specific CVE ID to filter by.
3. An optional Start and End date (MM/DD/YYYY).
4. A comma-separated list of any additional fields you want included in the report.
5. Your preferred output format (csv or json).

## Outputs
Depending on your selection, the script will generate files stamped with the current timestamp in your working directory.

#### CSV Output (Generates 2 Files)
- `CVE_List_{timestamp}.csv`: A high-level summary listing all confirmed CVEs and the total number of affected assets for each.
- `Assets_Per_CVEs_{timestamp}.csv`: A detailed breakdown listing each individual asset mapped to its confirmed CVE. This includes the mandatory fields (CVE ID, Asset ID, Asset Name) plus any optional fields you selected during runtime.

#### JSON Output (Generates 1 File)
- `Assets_Per_CVE_{timestamp}.json`: A nested JSON file containing all confirmed CVEs, the total asset count for each, and a dictionary mapping each Asset ID to a list containing the Asset Name and your selected custom fields.