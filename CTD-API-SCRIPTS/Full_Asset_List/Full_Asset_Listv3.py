# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Description:
# This script connects to a Claroty CTD server, authenticates, and retrieves
# a comprehensive list of all assets. It extracts specific fields (chosen 
# dynamically by the user) and saves them to either a CSV or JSON file based 
# on user preference.
# =============================================================================

import requests
import urllib3
import json
import sys
import csv
import datetime
import getpass

urllib3.disable_warnings()

def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth_payload))
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

def get_fields_input():
    """Prompts the user to dynamically select which fields to return from the API."""
    print("\n--- Field Selection ---")
    mandatory_fields = ['id', 'name']
    
    # All available optional fields supported by the endpoint
    optional_fields = [
        'ipv4', 'ipv6', 'mac', 'os', 'model', 'vendor', 'firmware', 
        'site_id', 'resource_id', 'timestamp', 'last_updated', 'approved', 
        'valid', 'ghost', 'parsed', 'special_hint', 'risk_level', 
        'last_entity_seen', 'site_name', 'network_id', 'subnet_id', 
        'virtual_zone_id', 'virtual_zone_name', 'active_queries_names', 
        'active_tasks_names', 'purdue_level', 'first_seen', 'vlan', 'fdl', 
        'address', 'gateway', 'asset_type', 'class_type', 'hostname', 
        'plc_slots', 'project_parsed', 'serial_number', 'criticality', 
        'domain_workgroup', 'default_gateway', 'edge_last_run', 'edge_id', 
        'installed_antivirus', 'has_interfaces', 'old_ips', 'state', 
        'custom_informations', 'patch_count', 'code_sections', 
        'installed_programs_count', 'usb_devices_count', 'os_build', 
        'os_architecture', 'os_service_pack', 'asset_insight', 'display_name', 
        'protocol', 'last_seen', 'num_alerts', 'children', 'network', 'subnet', 
        'subnet_tag', 'subnet_type', 'custom_attributes', 'insight_names', 'risk_score'
    ]

    print("Mandatory fields (Always included): id, name")
    print("Optional fields to include:")
    
    # Display the fields in a clean column format
    for i, field in enumerate(optional_fields, start=1):
        print(f"  {i:>2}. {field}")

    selections = input("\nEnter numbers or ranges (e.g., 1, 4-8, 12) to include (or press Enter to just pull mandatory fields): ").strip()    
    selected_fields = list(mandatory_fields)

    if selections:
        try:
            indices = set()  # Use a set to prevent duplicate indices if ranges overlap
            
            for part in selections.split(','):
                part = part.strip()
                if not part:
                    continue
                
                if '-' in part:
                    start_str, end_str = part.split('-', 1)
                    start = int(start_str.strip())
                    end = int(end_str.strip())
                    
                    if start <= end:
                        indices.update(range(start, end + 1))
                    else:
                        indices.update(range(end, start + 1))
                else:
                    if part.isdigit():
                        indices.add(int(part))
            
            for index in sorted(indices):
                if 1 <= index <= len(optional_fields):
                    field_name = optional_fields[index - 1]
                    if field_name not in selected_fields:
                        selected_fields.append(field_name)
                        
        except Exception as e:
            print("Error parsing field selection. Defaulting to mandatory fields only.")

    return selected_fields

def fetch_all_assets(ctd_ip, headers, fieldnames):
    """Paginates through the asset endpoint and formats the requested fields."""
    print("\nFetching Assets...")
    parsed_assets = []
    page = 1

    fields_param = ",;$".join(fieldnames)
    
    while True:
        print(f" - Processing page {page}...")
        
        asset_params = {
            'page': str(page),
            'per_page': '500',
            'ghost__exact': 'false',
            'valid__exact': 'true',        
            'special_hint__exact': '0', # 0 = eUnicast
            'site_id__exact' : '1',
            'fields': fields_param # Server-side filtering
        }

        # The 'auth: inherit auth from parent' payload as required by some Claroty endpoints
        body_data = json.dumps({'auth': 'inherit auth from parent'})

        response = requests.get(f"https://{ctd_ip}/ranger/assets",
                                verify=False, stream=True,
                                data=body_data, headers=headers, params=asset_params)

        data = response.json()

        if 'objects' in data and isinstance(data['objects'], list) and data['objects']:
            asset_list = data['objects']
            
            for asset in asset_list:
                row_data = {}
                
                for field in fieldnames:
                    value = asset.get(field)
                    
                    if value is None:
                        row_data[field] = "None"
                    elif isinstance(value, list):
                        if len(value) == 0:
                            row_data[field] = "None"
                        else:
                            row_data[field] = ", ".join(str(v) for v in value)
                    else:
                        row_data[field] = str(value).strip() or "None"
                
                parsed_assets.append(row_data)
            
            page += 1
        else:
            print("Asset extraction complete.\n")
            break
            
    return parsed_assets

def export_to_csv(timestamp, parsed_assets, fieldnames):
    """Exports the processed asset list to a CSV file."""
    filename = f"total_assets_{timestamp}.csv"
    
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(parsed_assets)
        
    print(f"Data written to file: {filename}")

def export_to_json(timestamp, parsed_assets, fieldnames):
    """Exports the processed asset list dynamically to a JSON file."""
    filename = f"total_assets_{timestamp}.json"
    output_data = []
    
    for asset in parsed_assets:
        formatted_object = {}
        # Dynamically build the JSON object based on the requested fields
        for field in fieldnames:
            # Map 'id' to 'asset id' to match requested schema, leave others as-is
            key = "asset id" if field == "id" else field
            formatted_object[key] = asset.get(field, "None")
            
        output_data.append(formatted_object)
        
    with open(filename, mode='w', encoding='utf-8') as json_file:
        json.dump(output_data, json_file, indent=4)
        
    print(f"Data written to file: {filename}")

def main():
    """Main function."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("=== Claroty CTD Asset Extractor ===")
    
    # Setup & Authentication
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    headers = authenticate(ctd_ip, username, password)

    # Output preferences & Field selection
    output_format = get_output_preference()
    asset_fieldnames = get_fields_input()

    # Fetch Data
    parsed_assets = fetch_all_assets(ctd_ip, headers, asset_fieldnames)
    total_assets = len(parsed_assets)

    # Route Output
    if total_assets > 0:
        if output_format == 'csv':
            export_to_csv(timestamp, parsed_assets, asset_fieldnames)
        elif output_format == 'json':
            export_to_json(timestamp, parsed_assets, asset_fieldnames)
    else:
        print("No valid assets found to export.")

    # Final Summary
    print("-" * 35)
    print("Summary of Asset Processing")
    print("-" * 35)
    print(f"Total valid assets saved : {total_assets:,}")
    print("-" * 35)
    print("Script execution complete.")

if __name__ == "__main__":
    main()