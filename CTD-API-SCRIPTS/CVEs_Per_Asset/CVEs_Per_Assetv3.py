# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
#
# Description:
# This script connects to a Claroty CTD server, authenticates, and retrieves 
# a list of vulnerable assets, along with confirmed CVEs found by CTD per asset. Output is modularized
# and can be exported to either CSV or a nested JSON format based on user input.
# It also includes an optional time filter to only pull recently seen assets.
# =============================================================================

import requests
import urllib3
import sys
import csv
import datetime
import json
import getpass

urllib3.disable_warnings()

# Authentication & User Input
def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    print("Successful Login.\n")
    return {
        'Authorization': auth_data['token'],
        'Content-Type': 'application/json'
    }

def get_output_preference():
    """Prompts the user to choose between CSV or JSON output."""
    while True:
        choice = input("Would you like the output in CSV or JSON format? (Enter 'csv' or 'json'): ").strip().lower()
        if choice in ['csv', 'json']:
            return choice
        print("Invalid input. Please type 'csv' or 'json'.")

def get_relative_time_filter():
    """Prompts the user for a relative timeframe to filter assets by last seen date."""
    print("\n--- Time Filter ---")
    days_input = input("Pull assets last seen within how many days ago? (Leave blank for all time): ").strip()
    
    if days_input.isdigit():
        print(f"Filtering for assets last seen within the last {days_input} days.\n")
        return days_input
    else:
        print("No time filter applied. Pulling all relevant assets.\n")
        return None

def get_fields_input():
    """Prompts the user for additional fields to pull from the API."""
    print("\n--- Field Selection ---")
    mandatory_fields = ['cve_id', 'asset_id', 'asset_name']
    
    optional_fields = [
        'cvss_v3_score', 'epss_score', 'actively_exploited', 
        'advisory_names', 'vulnerability_type', 'detection_date', 'description'
    ]

    print("Mandatory fields (Always included): cve_id, asset_id, asset_name")
    print("Optional fields to include:")
    for i, field in enumerate(optional_fields, start=1):
        display_name = "advisory" if field == "advisory_names" else field
        print(f"  {i}. {display_name}")

    selections = input("\nEnter a comma-separated list of numbers to include (or press Enter for default): ").strip()
    
    selected_fields = list(mandatory_fields)
    additional_fields = []

    if selections:
        try:
            indices = [int(x.strip()) for x in selections.split(',') if x.strip().isdigit()]
            for index in indices:
                if 1 <= index <= len(optional_fields):
                    field_name = optional_fields[index - 1]
                    if field_name not in selected_fields:
                        selected_fields.append(field_name)
                        additional_fields.append(field_name)
        except Exception as e:
            print("Error parsing field selection, defaulting to mandatory fields.")

    fields_param = ",;$".join(selected_fields)
    return fields_param, additional_fields

def prompt_asset_id_filter(asset_info):
    """Outputs all tracked assets in a clean table and prompts for an Asset ID filter."""
    print("\n--- Relevant Assets (Confirmed Vulnerabilities) ---")
    print(f"{'Asset ID':<10} | {'Asset Name'}")
    print("-" * 45)
    for a_id, info in asset_info.items():
        print(f"{str(a_id):<10} | {info['name']}")
    print("-" * 45)

    target_asset = input("\nEnter an Asset ID to filter by (or press Enter for all assets): ").strip()
    
    if not target_asset:
        print("No asset filter applied. Processing all relevant assets.\n")
        return None
    
    # Search for matching ID (handling int vs str input)
    for a_id in asset_info.keys():
        if str(a_id) == target_asset:
            print(f"Filtering for Asset ID: {a_id} ({asset_info[a_id]['name']})\n")
            return a_id
            
    print(f"Asset ID '{target_asset}' not found in the relevant assets list. Proceeding with all assets.\n")
    return None

def fetch_assets(ctd_ip, headers, relative_days):
    """Fetches valid unicast assets using server-side field filtering."""
    print("Fetching relevant assets...")
    asset_cve_counts = {}
    asset_cve_mapping = {}
    asset_info = {}
    page = 1
    
    auth_data_body = json.dumps({'auth': 'inherit auth from parent'})

    while True:
        params = {
            'page': str(page),
            'per_page': '500',
            'ghost__exact': 'false', 
            'special_hint__exact': '0',
            'site_id__exact': '1',
            'relevance__exact': '1', # ONLY pull assets that have confirmed CVEs
            'fields': 'id,;$name'
        }
        
        # Append the relative time filter if the user provided a number
        if relative_days:
            params['last_seen__relative_time'] = relative_days
        
        try:
            response = requests.get(f"https://{ctd_ip}/ranger/assets", verify=False, headers=headers, data=auth_data_body, params=params)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching assets: {e}")
            break
        
        if 'objects' in data and data['objects']:
            for asset in data['objects']:
                a_id = asset.get('id') or asset.get('asset_id')
                if not a_id:
                    continue
                    
                a_name = asset.get('name') or asset.get('hostname') or "Unknown"
                
                asset_info[a_id] = {'name': a_name, 'ip': asset.get('ip', '')}
                asset_cve_counts[a_id] = 0
                asset_cve_mapping[a_id] = []
                
            page += 1
        else:
            break
            
    print(f"Number of valid vulnerable assets tracked: {len(asset_info)}")
    return asset_cve_counts, asset_cve_mapping, asset_info

def fetch_cves(ctd_ip, headers, asset_cve_counts, asset_cve_mapping, fields_param, additional_fields):
    """Loops through the selected Asset ID(s) and fetches their specific confirmed CVEs."""
    print("Fetching confirmed CVEs for tracked assets...")
    
    total_assets = len(asset_cve_mapping)
    
    for index, a_id in enumerate(asset_cve_mapping.keys(), start=1):
        print(f"Processing Asset {index}/{total_assets} | ID: {a_id}...")
        page = 1
        
        while True:
            params = {
                'page': str(page),
                'per_page': '500',
                'site_id__exact': '1',
                'ghost__exact': 'false',
                'special_hint__exact': '0',
                'relevance__exact': '1', 
                'asset_id__exact': f"{a_id}-1",
                'fields': fields_param
            }
            
            try:
                response = requests.get(f"https://{ctd_ip}/ranger/asset-vulnerabilities", verify=False, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching CVEs for asset {a_id}: {e}")
                break
            
            if 'objects' in data and data['objects']:
                for mapping in data['objects']:
                    cve_id = mapping.get('cve_id')
                    if cve_id:
                        asset_cve_counts[a_id] += 1
                        
                        vuln_data = {'cve_id': cve_id}
                        for field in additional_fields:
                            vuln_data[field] = mapping.get(field)
                            
                        asset_cve_mapping[a_id].append(vuln_data)
                page += 1
            else:
                break


# Output Generation
def format_value(value):
    """Helper to format nested dicts and lists into strings for CSVs."""
    if isinstance(value, dict):
        return value.get('value', str(value))
    elif isinstance(value, list):
        return ", ".join(str(v) for v in value)
    elif value is None:
        return ""
    return str(value)

def export_to_csv(timestamp, asset_cve_counts, asset_cve_mapping, asset_info, additional_fields):
    """Handles writing the data to CSV files."""
    csv1_filename = f"Assets_CVE_Counts_List_{timestamp}.csv"
    try:
        with open(csv1_filename, mode='w', newline='', encoding='utf-8') as f1:
            writer1 = csv.DictWriter(f1, fieldnames=['Asset ID', 'Asset Name', 'CVE Count'])
            writer1.writeheader()
            for a_id, count in asset_cve_counts.items():
                name = asset_info.get(a_id, {}).get('name', 'Unknown')
                writer1.writerow({'Asset ID': a_id, 'Asset Name': name, 'CVE Count': count})
    except Exception as e:
        print(f"Error writing {csv1_filename}: {e}")
            
    csv2_filename = f"CVEs_Per_Assets_List_{timestamp}.csv"
    try:
        with open(csv2_filename, mode='w', newline='', encoding='utf-8') as f2:
            headers = ['Asset ID', 'Asset Name', 'Item', 'CVE ID']
            formatted_additional_fields = [f.replace('_', ' ').title() for f in additional_fields]
            headers.extend(formatted_additional_fields)
            
            writer2 = csv.DictWriter(f2, fieldnames=headers)
            writer2.writeheader()
            
            for a_id, cve_list in asset_cve_mapping.items():
                if not cve_list:
                    continue
                name = asset_info[a_id]['name']
                
                for item_num, cve_obj in enumerate(cve_list, start=1):
                    row = {
                        'Asset ID': a_id,
                        'Asset Name': name,
                        'Item': item_num,
                        'CVE ID': cve_obj['cve_id']
                    }
                    
                    for field, header_name in zip(additional_fields, formatted_additional_fields):
                        row[header_name] = format_value(cve_obj.get(field))
                        
                    writer2.writerow(row)
    except Exception as e:
        print(f"Error writing {csv2_filename}: {e}")
                
    print(f"\nCSVs Exported:\n - {csv1_filename}\n - {csv2_filename}")

def export_to_json(timestamp, asset_cve_mapping, asset_info):
    """Handles writing the data to a formatted JSON file."""
    json_filename = f"CVEs_Per_Assets_List_{timestamp}.json"
    output_data = []
    
    for a_id, cves in asset_cve_mapping.items():
        if cves:
            output_data.append({
                "asset id": a_id,
                "asset name": asset_info[a_id]['name'],
                "cves count": len(cves),
                "vulnerabilities": cves
            })
            
    try:
        with open(json_filename, mode='w', encoding='utf-8') as json_file:
            json.dump(output_data, json_file, indent=4)
        print(f"\nJSON Exported:\n - {json_filename}")
    except Exception as e:
        print(f"Error writing {json_filename}: {e}")


# Main 
def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("=== Claroty CTD CVEs Per Asset Refined Script ===")
    
    # 1. User Inputs
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    headers = authenticate(ctd_ip, username, password)

    fields_param, additional_fields = get_fields_input()
    output_format = get_output_preference()
    relative_days = get_relative_time_filter()
    
    # 2. Fetch Assets
    asset_cve_counts, asset_cve_mapping, asset_info = fetch_assets(ctd_ip, headers, relative_days)
    
    if not asset_info:
        print("No assets matched the criteria. Exiting script.")
        sys.exit(0)
        
    # 3. Prompt for Single Asset Filter
    selected_asset_id = prompt_asset_id_filter(asset_info)
    if selected_asset_id is not None:
        asset_cve_counts = {selected_asset_id: asset_cve_counts[selected_asset_id]}
        asset_cve_mapping = {selected_asset_id: asset_cve_mapping[selected_asset_id]}
        asset_info = {selected_asset_id: asset_info[selected_asset_id]}

    # 4. Fetch CVEs for Selected Asset(s)
    fetch_cves(ctd_ip, headers, asset_cve_counts, asset_cve_mapping, fields_param, additional_fields)
    
    # 5. Validation & Export
    assets_with_vulns = sum(1 for cves in asset_cve_mapping.values() if cves)
    print(f"\nTotal assets with confirmed vulnerabilities processed: {assets_with_vulns}")
    
    if output_format == 'csv':
        export_to_csv(timestamp, asset_cve_counts, asset_cve_mapping, asset_info, additional_fields)
    elif output_format == 'json':
        export_to_json(timestamp, asset_cve_mapping, asset_info)
        
    print("\nScript execution complete.")

if __name__ == "__main__":
    main()