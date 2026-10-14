# Full Asset List Exporter

This script connects to a Claroty CTD instance, authenticates, and retrieves a comprehensive inventory of all valid assets in your environment. It features an interactive command-line interface that allows you to dynamically select which asset fields to extract and choose your preferred export format.

## Features

*   **Comprehensive Inventory:** Retrieves all valid, active unicast assets from the CTD environment.
*   **Dynamic Field Selection:** Interactively choose from dozens of available asset data points (e.g., `ipv4`, `mac`, `vendor`, `os`, `firmware`, `risk_score`) to include in your report without needing to edit the code. 
*   **Flexible Output:** Export your custom asset inventory to either a CSV file or a formatted JSON file.
*   **`Full_Asset_List_PS.ps1`**: same script, runnable through powershell. 

## Prerequisites

Ensure you have Python 3 installed along with the `requests` library. You can install the required dependencies in the `requirements.txt` file in the root directory, or by using:

```bash
pip install requests urllib3
```

## Usage
Navigate to the directory the script lives in and run the script from your terminal:

```Bash
python Full_Asset_Listv3.py
```

Upon execution, the script will prompt you for:

1. Your CTD IP/Hostname and credentials.
2. Your preferred output format (csv or json).
3. A comma-separated list of any additional asset fields you want to include in the output (the script will provide a numbered list of all available fields for you to choose from).

## Outputs
Depending on your format selection, the script will generate a file stamped with the current timestamp in your working directory:

-  `total_assets_{timestamp}.csv`: A csv file containing all extracted assets, with columns corresponding to your selected fields (always including id and name as mandatory fields).
- `total_assets_{timestamp}.json`: A formatted JSON file containing an array of all extracted assets and their dynamically selected data points.