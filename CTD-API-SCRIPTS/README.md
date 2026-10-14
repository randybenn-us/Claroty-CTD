# CTD API Scripts

This is a collection of Python scripts to automate commonly requested or custom tasks using the CTD REST API. Running these scripts will query your CTD instance and generate one or more CSV files detailing specific relationships as per the script.

### Prerequisites

**Python 3.1x or later** (3.14 recommended).

```bash
pip install -r requirements.txt
```
Request an API key for NVD, create a `.env` file and enter the key as `NVD_KEY = "your key"`

### Current Scripts

1. **`Assets_Per_CVE`**: Given CTD credentials, this script exports a comprehensive mapping of confirmed CVEs and the specific assets they affect. It features an interactive menu to filter by date or specific CVEs, and allows dynamic selection of asset fields to export as CSV or JSON. ***(Available in powershell)***

2. **`CVEs_Per_Asset`**: Given CTD credentials, this script exports a list of assets and all their associated confirmed vulnerabilities. It includes interactive options to filter by Asset ID or last-seen dates, and allows dynamic selection of vulnerability data points to export as CSV or JSON. ***(Available in powershell)***

3. **`Full_Asset_List`**: Given CTD credentials, this script retrieves a complete inventory of all active unicast assets in the environment. It allows users to interactively choose from dozens of available asset fields (e.g., IPs, MACs, OS, risk scores) to build a custom CSV or JSON report. ***(Available in powershell)***

4. `Get_Edge_Host.py`: A lightweight diagnostic script that identifies all active Edge hosts within a CTD environment and prints their details directly to the terminal. *(See the `Get_Edge_Progs` directory for more details)*.

5. `Get_Edge_Progs.py`: Extracts a comprehensive inventory of installed 3rd-party programs from specific or all active Edge hosts, exporting the results to CSV or JSON. It also cross-references each program to indicate whether its vulnerabilities are already natively tracked by CTD. *(See the `Get_Edge_Progs` directory for detailed output formatting and usage)*.

6. **`CPE_Name.py`**: Given a CSV list of software programs, queries the NVD database, and outputs a generalized base CPE (Common Platform Enumeration) identifier alongside a match confidence score for each program. *(See the `NVD_Matching` directory for detailed output formatting and usage).*

7. **`CVE_Matches.py`**: Given the output from `CPE_Name.py`, queries the NVD API to find Windows-applicable CVEs matching the specific CPE and version, outputting vulnerability details including CVSS scores and CISA KEV status. *(See the `NVD_Matching` directory for detailed output formatting and usage).*

### Instructions
Clone the repository, install requirements (including an NVD API key for `CPE_Name.py` and `CVE_Matches.py`, stored as an environment variable in your system), and run the scripts (VSCode or other IDE recommended). Running the scripts will prompt you for the hostname or IP, username, and password of your CTD instance. Once inputed, the scripts will query the CTD REST API and create the corresponding CSVs in your local directory. 

### Future Development
- CVEs for Linux OS script
