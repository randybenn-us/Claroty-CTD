# Edge Host & Programs Extractor

This directory contains two related scripts designed to interact with your Claroty CTD instance. Together, they identify active Edge hosts in your environment and extract a comprehensive inventory of 3rd-party programs installed on those hosts.

## High-Level Overview

*   **`Get_Edge_Host.py`**: A lightweight diagnostic/helper script. It queries the CTD REST API for all active assets, filters for those with an assigned `edge_id` (typically Windows/Linux hosts running the Edge sensor), and prints a cleanly formatted table of the results directly to your terminal. It does not generate any external files.
*   **`Get_Edge_Progsv3.py`**: The primary extraction script. It leverages the host-finding logic from the helper script, presents you with a list of detected Edge hosts, and allows you to pull the installed 3rd-party programs for a single specific host or *all* detected hosts at once. It cross-references these programs with Claroty's native tracking capabilities and exports the results to CSV or JSON.
*   **`Get_Edge_Progs_PS.ps1`**: same script, runnable through powershell. 


## Prerequisites & Requirements

Ensure you have Python 3 installed along with the `requests` library. You can install the required dependencies in the `requirements.txt` file in the root directory, or by using:

```bash
pip install requests urllib3
```
**IMPORTANT:** To run `Get_Edge_Progsv3.py` successfully, the file **`cve_program_matcher_cut.csv`** MUST be located in the exact same directory as the Python script. This file contains the local dictionary used to determine if a program's vulnerabilities are natively tracked by CTD.

## Usage

Run either script from your terminal:

```bash
# To simply identify Edge hosts
python Get_Edge_Host.py

# To extract programs from Edge hosts
python Get_Edge_Progsv3.py
```

Upon executing Get_Edge_Progsv3.py, you will be prompted to:

1. Enter your CTD IP/Hostname and credentials.
2. Select your preferred output format (csv or json).
3. View the detected Edge assets and type the Asset ID of the specific host you want to query, or simply press Enter to process every detected Edge host automatically.

## Output
`Get_Edge_Host.py` Output: terminal output only. Displays Asset ID, Asset Name, Edge ID, OS, and Subnet.

`Get_Edge_Progsv3.py` Output: Depending on your format selection, the script generates one file per processed host, named as {asset_id}_programs_list_{timestamp}.csv or .json.

The output contains the following data points:
- `program`: The name of the installed software.
- `vendor`: The manufacturer or publisher of the software.
- `version`: The specific version number installed on the host.
- `in_CTD`: Indicates if Claroty natively tracks Known Exploited Vulnerabilities (KEVs) for this specific software vendor/program combination.
    - "yes": The program is natively tracked by CTD (found in `cve_program_matcher_cut.csv`).
    - "no": The program is not natively tracked by CTD.