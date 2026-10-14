import getpass
import json
import requests
import datetime
import sys
import urllib3
import csv
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Authentication & Setup
def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
        response.raise_for_status()
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to the server: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    token = auth_data.get('token')
    if not token:
        print("Authentication Failed: No token returned by the server.")
        sys.exit(1)

    print("Successful Login.\n")
    return {
        'Authorization': token,
        'Content-Type': 'application/json'
    }

def get_output_preference():
    """Prompts the user to choose between CSV or JSON output."""
    while True:
        choice = input("Would you like the output in CSV or JSON format? (Enter 'csv' or 'json'): ").strip().lower()
        if choice in ['csv', 'json']:
            return choice
        print("Invalid input. Please type 'csv' or 'json'.")


# Asset & Program Querying
def get_edge_assets(ctd_ip, headers):
    """Fetches all assets from CTD that have active edge_ids."""
    print("Querying assets for active edge_ids...")
    raw_assets = []
    asset_page = 1
    asset_per_page = 500
    
    while True:
        params = {
            'page': str(asset_page),
            'per_page': str(asset_per_page),
            'fields': 'id,;$name,;$edge_id,;$subnet,;$os'
        }
        asset_url = f"https://{ctd_ip}/ranger/assets"
        
        try:
            response = requests.get(asset_url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            data = response.json()
            
            objects = data.get("objects", [])
            raw_assets.extend(objects)
            
            if len(objects) < asset_per_page:
                break
                
            asset_page += 1
            
        except Exception as e:
            print(f"Failed to fetch assets on page {asset_page}: {e}")
            sys.exit(1)
            
    # filter out null edge_ids
    edge_assets = [
        {
            'id': a.get('id'),
            'resource_id': a.get('resource_id', f"{a.get('id')}-1"),
            'name': a.get('name', a.get(';$name', 'Unknown')),
            'edge_id': a.get('edge_id', a.get(';$edge_id')),
            'os': a.get('os', a.get(';$os', 'Unknown')),
            'subnet': a.get('subnet', a.get(';$subnet', 'Unknown'))
        }
        for a in raw_assets 
        if a.get('edge_id', a.get(';$edge_id')) is not None 
        and str(a.get('edge_id', a.get(';$edge_id'))).strip() != ""
    ]
    
    return edge_assets

def prompt_edge_host_selection(edge_assets):
    """Outputs detected Edge hosts to terminal and lets user pick an ID or process all."""
    if not edge_assets:
        print("No Edge assets found in this environment. Exiting.")
        sys.exit(0)

    print(f"\n--- Detected Edge Assets ({len(edge_assets)} Found) ---")
    print(f"{'Asset ID':<10} | {'Asset Name':<30} | {'Edge ID':<38} | {'OS'}")
    print("-" * 105)
    for asset in edge_assets:
        print(f"{str(asset['id']):<10} | {str(asset['name']):<30} | {str(asset['edge_id']):<38} | {str(asset['os'])}")
    print("-" * 105)

    target_id = input("\nEnter an Asset ID to pull programs for a specific Edge host (or press Enter for ALL hosts): ").strip()

    if not target_id:
        print("Processing ALL Edge hosts.\n")
        return edge_assets

    # Filter for the chosen host
    selected = [a for a in edge_assets if str(a['id']) == target_id]
    if not selected:
        print(f"Asset ID '{target_id}' not found in detected Edge assets. Proceeding with ALL Edge hosts.\n")
        return edge_assets

    print(f"Filtering for selected Edge host: ID {selected[0]['id']} ({selected[0]['name']})\n")
    return selected

def fetch_installed_programs(ctd_ip, headers, asset):
    """Fetches installed 3rd-party programs for a specific Edge host resource ID."""
    asset_id = asset['id']
    # Uses resource_id if available, otherwise appends -1 to format as site resource ID
    resource_id = asset.get('resource_id') or f"{asset_id}-1"
    
    print(f"Fetching installed programs for Asset ID {asset_id} ({asset['name']})...")
    all_programs = []
    page = 1
    per_page = 500
    
    while True:
        params = {
            'fields': 'name,;$version,;$vendor',
            'sort': 'name',
            'page': str(page),
            'per_page': str(per_page),
            'asset_rid__exact': str(resource_id)
        }
        url = f"https://{ctd_ip}/ranger/ranger_api/asset_installed_programs"
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=False)
            response.raise_for_status()
            
            data = response.json()
            objects = data.get("objects", [])
            all_programs.extend(objects)
            
            if len(objects) < per_page:
                break
                
            page += 1
            
        except requests.exceptions.RequestException as e:
            print(f"Error pulling programs on page {page} for Asset {asset_id}: {e}")
            break
            
    return all_programs


# Native CVE Matcher Logic
def load_cve_matcher_map(csv_filepath):
    """Loads local CTD CVE match dictionary from CSV if present."""
    matcher_map = defaultdict(list)
    try:
        with open(csv_filepath, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None) 
            for row in reader:
                if len(row) >= 2:
                    vendor = row[0].strip().lower()
                    program = row[1].strip().lower()
                    if vendor and program:
                        matcher_map[vendor].append(program)
        print(f"Loaded {sum(len(v) for v in matcher_map.values())} reference programs across {len(matcher_map)} vendors from {csv_filepath}.\n")
    except FileNotFoundError:
        print(f"WARNING: {csv_filepath} not found. 'in_CTD' tracking will default to 'no'.\n")
    
    return matcher_map

def check_in_ctd(api_vendor, api_program, matcher_map):
    """Checks if the program vendor and string match the local CTD database map."""
    if not matcher_map:
        return "no"
        
    api_vendor_norm = api_vendor.strip().lower()
    api_prog_norm = api_program.strip().lower()

    if api_vendor_norm in matcher_map:
        for csv_program in matcher_map[api_vendor_norm]:
            if csv_program in api_prog_norm:
                return "yes"
                
    return "no"


# Exporting
def export_programs(timestamp, asset, programs_list, matcher_map, output_format):
    """Exports programs list for a single host to CSV or JSON."""
    asset_id = asset['id']
    asset_name = asset['name']
    
    if output_format == 'csv':
        filename = f"{asset_id}_programs_list_{timestamp}.csv"
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(['program', 'vendor', 'version', 'in_CTD'])
                
                for obj in programs_list:
                    program = obj.get('name', '')
                    vendor = obj.get(';$vendor', obj.get('vendor', ''))
                    version = obj.get(';$version', obj.get('version', ''))
                    in_ctd_status = check_in_ctd(vendor, program, matcher_map)
                    
                    writer.writerow([program, vendor, version, in_ctd_status])
                    
            print(f"Successfully exported CSV for Asset ID {asset_id} ({asset_name}) -> {filename}")
        except Exception as e:
            print(f"Failed to write CSV for Asset {asset_id}: {e}")

    elif output_format == 'json':
        filename = f"{asset_id}_programs_list_{timestamp}.json"
        json_output = {
            "asset_id": asset_id,
            "asset_name": asset_name,
            "edge_id": asset['edge_id'],
            "program_count": len(programs_list),
            "programs": []
        }
        
        for obj in programs_list:
            program = obj.get('name', '')
            vendor = obj.get(';$vendor', obj.get('vendor', ''))
            version = obj.get(';$version', obj.get('version', ''))
            in_ctd_status = check_in_ctd(vendor, program, matcher_map)
            
            json_output["programs"].append({
                "program": program,
                "vendor": vendor,
                "version": version,
                "in_CTD": in_ctd_status
            })
            
        try:
            with open(filename, mode='w', encoding='utf-8') as json_file:
                json.dump(json_output, json_file, indent=4)
            print(f"Successfully exported JSON for Asset ID {asset_id} ({asset_name}) -> {filename}")
        except Exception as e:
            print(f"Failed to write JSON for Asset {asset_id}: {e}")


# Main Execution
def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("=== Claroty CTD Edge Asset Programs Extractor ===")
    
    # 1. Credentials
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    
    # 2. Setup & Matcher Map
    headers = authenticate(ctd_ip, username, password)
    
    matcher_csv = "cve_program_matcher_cut.csv"
    matcher_map = load_cve_matcher_map(matcher_csv)

    # 3. Query Edge Hosts & Prompt Selection
    all_edge_assets = get_edge_assets(ctd_ip, headers)
    target_assets = prompt_edge_host_selection(all_edge_assets)
    output_format = get_output_preference()


    # 4. Process Each Selected Host
    print("\nStarting program extraction...")
    for asset in target_assets:
        programs_list = fetch_installed_programs(ctd_ip, headers, asset)
        print(f"Found {len(programs_list)} 3rd-party programs for Asset ID {asset['id']}.")
        
        if programs_list:
            export_programs(timestamp, asset, programs_list, matcher_map, output_format)
        else:
            print(f"No installed programs returned for Asset ID {asset['id']}.")
        print("-" * 50)

    print("Script execution complete.")

if __name__ == "__main__":
    main()