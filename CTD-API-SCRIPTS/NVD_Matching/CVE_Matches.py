import csv
import requests
import time
import os
import json
from dotenv import load_dotenv

# CONFIGURATION
INPUT_CSV = input("Enter input CSV file name: ").strip()
OUTPUT_CSV = input("Enter output CSV file name: ").strip()
ONLY_KEVS_INPUT = input("Only extract Known Exploited Vulnerabilities (KEVs)? (y/n): ").strip().lower()
ONLY_KEVS = ONLY_KEVS_INPUT in ['y', 'yes']

NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

load_dotenv()

API_KEY = os.getenv("NVD_KEY")

HEADERS = {}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

MAX_CVES_PER_PROGRAM = int(input("Enter maximum CVEs to list per program: ") or 100)
SLEEP_DELAY = 0.6


# HELPER FUNCTIONS
def build_versioned_cpe(cpe_name, version):
    parts = cpe_name.split(":")

    if len(parts) < 13:
        raise ValueError(f"Invalid CPE: {cpe_name}")
        
    clean_version = version.split()[0]
    parts[5] = clean_version

    return ":".join(parts)

def get_cisa_kev_name(cve_data):
    """
    Extracts the CISA vulnerability name if the CVE is on the KEV catalog.
    Returns 'N/A' if it is not a KEV.
    """
    return cve_data.get("cisaVulnerabilityName", "N/A")

def get_cvss_metrics(metrics):
    """
    Extracts CVSS version, base score, and base severity dynamically.
    Prioritizes the first Primary metric of the highest available CVSS version.
    """
    #Sort keys descending (V40 > V31 > V30 > V2)
    sorted_metric_keys = sorted(metrics.keys(), reverse=True)
    
    def extract_data(item):
        cvss_data = item.get("cvssData", {})
        version = cvss_data.get("version", "N/A")
        score = cvss_data.get("baseScore", "N/A")
        
        # Fallback: v3/v4 has baseSeverity inside cvssData, v2 has it outside.
        severity = cvss_data.get("baseSeverity") or item.get("baseSeverity", "N/A")
        
        return version, score, severity

    # Search for the highest version "Primary" metric
    for key in sorted_metric_keys:
        for metric_item in metrics[key]:
            if metric_item.get("type") == "Primary":
                return extract_data(metric_item)
                
    # Fallback: Grab the highest version "Secondary" metric if no Primary exists
    for key in sorted_metric_keys:
        if metrics[key]:
            return extract_data(metrics[key][0])
            
    return "N/A", "N/A", "N/A"


def evaluate_node(node, target_vendor, target_product, parent_operator):
    node_operator = node.get("operator", "OR").upper()
    negate = node.get("negate", False)
    cpe_matches = node.get("cpeMatch", [])
    
    match_results = []
    
    for match in cpe_matches:
        criteria = match.get("criteria", "")
        cpe_fields = criteria.split(":")
        
        if len(cpe_fields) > 10:
            vuln_vendor = cpe_fields[3].lower()
            vuln_product = cpe_fields[4].lower()
            
            # target application (exact vendor/product matches)
            is_target_app = (vuln_vendor == target_vendor and vuln_product == target_product)

            if is_target_app:
                target_sw = cpe_fields[10].lower()
                match_results.append(target_sw in ['*', '-'] or 'windows' in target_sw)
            
            # Operating System requirement (Index 2 denotes App vs OS vs Hardware)
            elif cpe_fields[2] == "o":
                is_windows_os = ("windows" in vuln_vendor or "windows" in vuln_product)
                match_results.append(is_windows_os)
                
            # unrelated application
            else:
                match_results.append(True if node_operator == "AND" else False)

    if not match_results:
        return False

    node_outcome = all(match_results) if node_operator == "AND" else any(match_results)
    return not node_outcome if negate else node_outcome


def is_windows_applicable(vuln, target_vendor, target_product):
    configurations = vuln.get("cve", {}).get("configurations", [])
    if not configurations:
        return True  

    for config in configurations:
        config_operator = config.get("operator", "AND").upper()
        
        node_results = [
            evaluate_node(node, target_vendor, target_product, config_operator)
            for node in config.get("nodes", [])
        ]
        
        if node_results:
            config_outcome = all(node_results) if config_operator == "AND" else any(node_results)
            if config_outcome:
                return True
                
    return False

# MAIN API CALL
def query_cves(cpe_string, only_kevs=False):
    query_fields = cpe_string.split(":")
    target_vendor = query_fields[3].lower() if len(query_fields) > 3 else ""
    target_product = query_fields[4].lower() if len(query_fields) > 4 else ""
    request_url = f"{NVD_CVE_API_URL}?noRejected"
    
    if only_kevs:
        request_url += "&hasKev"

    response = requests.get(
        request_url,
        params={"virtualMatchString": cpe_string},
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    cves = []

    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id")
        
        if not cve_id:
            continue

        if is_windows_applicable(vuln, target_vendor, target_product):
            
            cisa_kev = get_cisa_kev_name(cve_data)
            cvss_version, base_score, base_severity = get_cvss_metrics(cve_data.get("metrics", {}))
            
            cves.append({
                "id": cve_id,
                "cvss_version": cvss_version,
                "base_score": base_score,
                "base_severity": base_severity,
                "cisa_kev": cisa_kev
            })

        if len(cves) >= MAX_CVES_PER_PROGRAM:
            break

    return cves


# MAIN
def main():
    start_time = time.time()

    duplicate_count = 0
    total_programs = 0
    cpe_matched_programs = 0
    unique_cpe_queries = 0
    total_found_cves = 0

    previous_query_cpe = None

    if ONLY_KEVS: 
        print("Staring query for all matching KEVs...")
        output_val = "KEV"
    else:
        print("Starting query for all matching CVEs...")
        output_val = "CVE"

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow([
            "Program", "Version", "Queried_CPE", "Confidence", "CVE", 
            "CVSS_Version", "Base_Score", "Base_Severity", "CISA_KEV"
        ])


    
    with open(INPUT_CSV, "r", encoding="utf-8-sig") as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            total_programs += 1

            program = row.get("program", "").strip()
            version = row.get("version", "").strip()
            cpe_name = row.get("cpe_name", "").strip()
            confidence = row.get("confidence", "").strip()

            if not cpe_name or cpe_name.upper() == "NOT_FOUND":
                continue

            cpe_matched_programs += 1

            if not version:
                continue

            try:
                query_cpe = build_versioned_cpe(cpe_name, version)

                if query_cpe == previous_query_cpe:
                    print(f"  -> Duplicate CPE Skipped: '{program}'")
                    duplicate_count += 1
                    continue

                print(f"Querying: {program} (v{version})")
                cves = query_cves(query_cpe, only_kevs=ONLY_KEVS)
                unique_cpe_queries += 1
                total_found_cves += len(cves)

                print(f"  -> Found {len(cves)} {output_val}s")

                with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as outfile:
                    writer = csv.writer(outfile)
                    if cves:
                        for cve in cves:
                            writer.writerow([
                                program, 
                                version, 
                                query_cpe, 
                                confidence, 
                                cve["id"],
                                cve["cvss_version"],
                                cve["base_score"],
                                cve["base_severity"],
                                cve["cisa_kev"]
                            ])
                
                previous_query_cpe = query_cpe

            except Exception as e:
                print(f"  [ERROR] {program}: {e}")
            
            time.sleep(SLEEP_DELAY)

    elapsed = time.time() - start_time
    minutes, seconds = divmod(elapsed, 60)

    print("\n===================================")
    print(f"Results saved to: {OUTPUT_CSV}")
    print(f"Total Programs: {total_programs}")
    print(f"CPE-Matched Programs: {cpe_matched_programs}")
    print(f"Unique CPEs Queried: {unique_cpe_queries}")
    print(f"Duplicate CPEs Skipped: {duplicate_count}")
    print(f"Total {output_val}s Found: {total_found_cves}")
    print(f"\nRuntime: {int(minutes)}m {seconds:.2f}s")

if __name__ == "__main__":
    main()