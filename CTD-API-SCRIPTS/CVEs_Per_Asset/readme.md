# CVEs Per Asset Exporter

This script connects to a Claroty CTD instance, authenticates, and retrieves a list of confirmed CVEs mapped to their respective assets. It features an interactive command-line interface to filter assets, select specific vulnerability data fields, and customize your export formats.

## Features

*   **Asset Filtering:** View a list of all vulnerable assets and optionally filter the report to pull CVEs for just one specific Asset ID.
*   **Relative Time Filter:** Optionally restrict the query to only pull assets last seen within a specified number of days.
*   **Custom Field Selection:** Dynamically include additional vulnerability details in your report (e.g., `cvss_v3_score`, `epss_score`, `actively_exploited`, `advisory_names`).
*   **Flexible Output:** Export the data into two relational CSV files or one comprehensive JSON file.
*   **`CVEs_Per_Asset_PS.ps1`**: same script, runnable through powershell. 


## Prerequisites

Ensure you have Python 3 installed along with the `requests` library. You can install the required dependencies in the `requirements.txt` file in the root directory, or by using:

```bash
pip install requests urllib3
```

## Usage
Navigate to the directory the script lives in and run the script from your terminal:

```Bash
python CVEs_Per_Assetv3.py
```

Upon execution, the script will prompt you for:

1. Your CTD IP/Hostname and credentials.
2. A comma-separated list of additional fields you want to include in the output.
3. Your preferred output format (csv or json).
4. An optional relative time filter (e.g., assets last seen within the last 7 days ago).
5. An optional specific Asset ID to filter by (or press Enter to process all relevant assets).

## Outputs
Depending on your format selection, the script will generate files stamped with the current timestamp in your working directory.

#### CSV Output (Generates 2 Files)
- `Assets_CVE_Counts_List_{timestamp}.csv`: A high-level summary listing all affected assets alongside their total count of confirmed CVEs.
- `CVEs_Per_Assets_List_{timestamp}.csv`: A detailed breakdown listing every confirmed CVE for each asset. It includes mandatory fields (Asset ID, Asset Name, Item, CVE ID) plus any of the optional fields you selected during runtime.

#### JSON Output (Generates 1 File)
- `CVEs_Per_Assets_List_{timestamp}.json`: A nested JSON file containing a list of assets, each detailing the asset id, asset name, cves count, and the complete array of vulnerabilities (with your selected fields) associated with that device.
