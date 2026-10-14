# NVD Matching Scripts

This directory contains two scripts designed to enrich software program lists with vulnerability data directly from the National Vulnerability Database (NVD). Given a list of programs, it finds matching CPE and CVE enumerations for all programs. The scripts are intended to be run sequentially.

## Prerequisites

Ensure you have Python 3 installed along with the `requests` library. You can install the required dependencies in the `requirements.txt` file in the root directory.

To avoid rate limiting and ensure the scripts run successfully, you must have an NVD API key. 
1. Request an API key from the NVD website.
2. Create a `.env` file in this directory.
3. Add your key to the file in the following format: `NVD_KEY="your_api_key_here"`

## Scripts Overview & Usage

### 1. CPE_Name.py
This script generates a CSV file that lists all programs AND each program's `cpeName` (if it exists). The `cpeName` is a unique identifier given to programs in the NVD database, typically formatted as `cpe:2.3:a:{vendor}:{program}:{version}:*:*:*:*:*:*:*`, where each `*` represents fields like edition, target software/hardware, etc.
- **Input:** A CSV file containing a list of programs (expected columns: `[program, vendor, version, in_ctd]`). This file can be exported from the `Get_Edge_Progsv3.py` script in the `Get_Edge_Progs/` folder.
- **Process**: Standardizes all program names, using "cleaned" program name to query the NVD database for the matching `cpeName` string. It matches results using strict substring matching first, and uses token-based matching as a fallback. 
- **Output**: A csv file with the columns `[program, vendor, version, in_ctd, cleaned_name, cpe_name, confidence]`

How to read output:

* `program, vendor, version, in_ctd`: these columns are the same as the input csv.
* `cleaned_name`: the standardized program name used to query the NVD CPE database
* `cpe_name`: the generalized base cpeName of the program, or `NOT_FOUND` if the program was not in the NVD CPE database.
* `confidence`: describes the certainty of a cpeName match.
    * "**F**" (Full): A strict title match was found and vetted. Think of this as a highly confident match.
    * "**P**" (Potential): A token-based match was found (all tokens appear, but not in a continuous string). This is not a confirmed full match. 
    * "**O**" (Override): The program search was overridden by a pre-mapped CPE string. (Used for common programs to reduce API calls. ie, Microsoft Office programs, common browsers like Chrome, etc). If a program title *contains* a string that is pre-mapped, it will automatically be overridden, hence, the match may not be 100% guaranteed.
    * "**N**" (N/A): no valid cpeName matches were found.

### 2. CVE_Matches.py
This script takes the standardized CPEs and queries the NVD database for known vulnerabilities. generating a csv file with all the CVEs found. 

**NOTE**: this script best works when matching CVEs to **3rd-party Windows Programs**. It does not return CVEs for programs that also require other specific hardware configurations. 
- **Input**: Takes in a CSV file containing valid CPE names and versions (the output from `CPE_Name.py`).
- **User Input**: Prompts for the input/output filenames, an optional limit on how many CVEs to fetch per program, and whether to strictly filter for only Known Exploited Vulnerabilities (KEVs).
- **Output**: A csv file with columns: `[Program, Version, Queried_CPE, Confidence, CVE, CVSS_Version, Base_Score, Base_Severity, CISA_KEV]`

How to read output:

* `Program, Version, Queried_CPE, Confidence`: These columns are carried over directly from the input CSV to maintain tracking.
* `CVE`: The unique identifier for the specific vulnerability (e.g., CVE-2024-12345).
* `CVSS_Version`: The version of the Common Vulnerability Scoring System used for the primary metric. The script prioritizes the newest available scoring system (e.g., 4.0, 3.1, 3.0, 2.0).
* `Base_Score`: The numerical CVSS severity score of the vulnerability, ranging from 0.0 to 10.0.
* `Base_Severity`: The qualitative severity rating (e.g., LOW, MEDIUM, HIGH, CRITICAL).
* `CISA_KEV`: The official CISA vulnerability name if the CVE is currently listed on the CISA Known Exploited Vulnerabilities catalog. If it is not on the catalog, this will read "N/A".

## Usage
Navigate to the directory these scripts live in, and run the scripts from your terminal sequentially (using output from `CPE_Name.py` as input for `CVE_Matches.py`).
```bash
python CPE_Name.py
python CVE_Matches.py
```