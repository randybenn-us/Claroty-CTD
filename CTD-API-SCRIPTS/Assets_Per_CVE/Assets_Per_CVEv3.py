# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
#
# Description:
# This script connects to a Claroty CTD server, authenticates, and retrieves 
# a list of confirmed CVEs along with associated assets. Output is modularized
# and can be exported to either CSV or a nested JSON format based on user input.
# It also includes an optional time filter to only pull recently seen assets.
# =============================================================================

import requests
import urllib3
import json
import sys
import getpass
import csv
import datetime
from collections import defaultdict

urllib3.disable_warnings()

# User Input Functions
def get_cve_input():
    """Asks the user to filter by a specific CVE or pull all."""
    print("\n--- CVE Filter ---")
    cve_id = input("Enter a specific CVE ID to filter by (or press Enter to pull all CVEs): ").strip()
    return cve_id if cve_id else None

def get_time_filter():
    """Prompts for start and end dates, converting them to UTC format with milliseconds and a trailing Z."""
    print("\n--- Time Filter ---")
    start_time_str = input("Enter a START time window (MM/DD/YYYY) or press Enter for none: ").strip()
    end_time_str = input("Enter an END time window (MM/DD/YYYY) or press Enter for none: ").strip()

    start_utc = None
    end_utc = None

    try:
        if start_time_str:
            dt_start = datetime.datetime.strptime(start_time_str, "%m/%d/%Y")
            # Format explicitly with milliseconds and the Z
            start_utc = dt_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            print(f"{start_utc}")
        if end_time_str:
            # Set to the end of the day for the end window
            dt_end = datetime.datetime.strptime(end_time_str, "%m/%d/%Y").replace(hour=23, minute=59, second=59)
            # Format explicitly with milliseconds and the Z
            end_utc = dt_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            print(f"{end_utc}")
    except ValueError:
        print("Invalid date format entered. Proceeding without time filters.")
        return None, None

    return start_utc, end_utc

def get_fields_input():
    """Prompts the user for additional fields to pull from the API."""
    print("\n--- Field Selection ---")
    mandatory_fields = ['cve_id', 'asset_id', 'asset_name']
    
    # Available optional fields (using asset_name instead of name to match endpoint standard)
    optional_fields = [
        'class_type', 'ipv4', 'ipv6', 'mac', 'vendor', 
        'os', 'model', 'firmware', 'serial_number', 'num_alerts', 'insight_names'
    ]

    print("Mandatory fields (Always included): cve_id, asset_id, asset_name")
    print("Optional fields to include:")
    for i, field in enumerate(optional_fields, start=1):
        print(f"  {i}. {field}")

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

    # Join the selected fields with the required delimiter
    fields_param = ",;$".join(selected_fields)
    return fields_param, additional_fields

def get_output_preference():
    """Prompts the user to choose between CSV or JSON output."""
    print("\n--- Output Format ---")
    while True:
        choice = input("Would you like the output in CSV or JSON format? (Enter 'csv' or 'json'): ").strip().lower()
        if choice in ['csv', 'json']:
            return choice
        print("Invalid input. Please type 'csv' or 'json'.")


# Auth/Endpoints
def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the authorization token."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth = {"username": username, "password": password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth))
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    print("Successful Login.\n")
    return auth_data['token']

def fetch_asset_vulnerabilities(ctd_ip, auth_token, target_cve, start_utc, end_utc, fields_param):
    """Fetches asset vulnerabilities from the environment with dynamic parameters."""
    print("Fetching asset vulnerabilities...")
    
    headers = {'Authorization': auth_token}
    raw_vulnerabilities = []
    page = 1

    while True:
        params = {
            'page': str(page),
            'per_page': '500',
            'site_id__exact': '1', 
            'ghost__exact': 'false',
            'special_hint__exact': '0', 
            'relevance__exact': '1', # only CONFIRMED CVEs
            'fields': fields_param
        }

        # Apply Optional Filters
        if target_cve:
            params['cve_id__exact'] = target_cve
        if start_utc:
            params['created_at__gte'] = start_utc
        if end_utc:
            params['created_at__lte'] = end_utc

        try:
            response = requests.get(f"https://{ctd_ip}/ranger/asset-vulnerabilities", verify=False, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data on page {page}: {e}")
            break

        if 'objects' in data and isinstance(data['objects'], list) and data['objects']:
            raw_vulnerabilities.extend(data['objects'])
            print(f"Fetched page {page} ({len(data['objects'])} records)...")
            page += 1
        else:
            break

    return raw_vulnerabilities


# Output Generation
def format_value(value):
    """Helper to cleanly format lists into strings for CSVs."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return value

def export_to_csv(timestamp, raw_data, additional_fields):
    """Exports to two distinct CSV files as requested."""
    cve_groups = defaultdict(list)
    
    for item in raw_data:
        cve_id = item.get("cve_id")
        if cve_id:
            cve_groups[cve_id].append(item)

    cve_list_filename = f"CVE_List_{timestamp}.csv"
    assets_per_cve_filename = f"Assets_Per_CVEs_{timestamp}.csv"

    # 1. Export CVE_List_{timestamp}.csv
    try:
        with open(cve_list_filename, mode='w', newline='', encoding='utf-8') as f1:
            writer = csv.writer(f1)
            writer.writerow(['CVE ID', 'Confirmed Asset Count'])
            for cve, assets in sorted(cve_groups.items()):
                writer.writerow([cve, len(assets)])
    except Exception as e:
        print(f"Error writing to {cve_list_filename}: {e}")

    # 2. Export Assets_Per_CVEs_{timestamp}.csv
    try:
        with open(assets_per_cve_filename, mode='w', newline='', encoding='utf-8') as f2:
            writer = csv.writer(f2)
            # Build dynamic header
            header = ['CVE ID', 'Item', 'Asset Name', 'Asset ID']
            header.extend([f.replace('_', ' ').title() for f in additional_fields])
            writer.writerow(header)
            
            for cve, assets in sorted(cve_groups.items()):
                for item_index, asset in enumerate(assets, start=1):
                    asset_name = asset.get('asset_name', 'Unknown')
                    asset_id = asset.get('asset_id', 'Unknown')
                    
                    row = [cve, item_index, asset_name, asset_id]
                    # Append dynamic fields
                    for field in additional_fields:
                        row.append(format_value(asset.get(field, '')))
                    
                    writer.writerow(row)
                    
        print(f"\nSuccessfully exported CSV reports:\n - {cve_list_filename}\n - {assets_per_cve_filename}")
    except Exception as e:
        print(f"Error writing to {assets_per_cve_filename}: {e}")

def export_to_json(timestamp, raw_data, additional_fields):
    """Exports data to a single JSON file following the requested nested schema."""
    cve_groups = defaultdict(list)
    
    for item in raw_data:
        cve_id = item.get("cve_id")
        if cve_id:
            cve_groups[cve_id].append(item)

    json_filename = f"Assets_Per_CVE_{timestamp}.json"
    output_data = []

    for cve, assets in sorted(cve_groups.items()):
        asset_mapping = {}
        
        for asset in assets:
            a_id = str(asset.get('asset_id', 'Unknown'))
            a_name = asset.get('asset_name', 'Unknown')
            
            # The list contains the asset name, followed by any additional requested fields
            asset_details = [a_name]
            for field in additional_fields:
                asset_details.append(asset.get(field))
            
            asset_mapping[a_id] = asset_details

        output_data.append({
            "cve id": cve,
            "asset count": len(assets),
            "asset list": asset_mapping
        })

    try:
        with open(json_filename, mode='w', encoding='utf-8') as json_file:
            json.dump(output_data, json_file, indent=4)
        print(f"\nSuccessfully exported JSON report:\n - {json_filename}")
    except Exception as e:
        print(f"Error writing to {json_filename}: {e}")


# Main
def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. Setup & Authentication
    print("=== CTD Assets Per CVE Exporter ===")
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    auth_token = authenticate(ctd_ip, username, password)

    # 2. Collect Preferences
    target_cve = get_cve_input()
    start_utc, end_utc = get_time_filter()
    fields_param, additional_fields = get_fields_input()
    output_format = get_output_preference()

    # 3. Fetch Data
    raw_vulnerabilities = fetch_asset_vulnerabilities(ctd_ip, auth_token, target_cve, start_utc, end_utc, fields_param)
    
    # 4. Process & Export
    if not raw_vulnerabilities:
        print("\nNo vulnerabilities found matching those criteria. Exiting.")
        sys.exit(0)

    print("\nProcessing data...")
    if output_format == 'csv':
        export_to_csv(timestamp, raw_vulnerabilities, additional_fields)
    elif output_format == 'json':
        export_to_json(timestamp, raw_vulnerabilities, additional_fields)

if __name__ == "__main__":
    main()