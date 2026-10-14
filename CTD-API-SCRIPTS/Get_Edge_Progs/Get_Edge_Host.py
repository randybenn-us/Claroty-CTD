import requests
import urllib3
import sys
import getpass

urllib3.disable_warnings()

# help funcs
def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
        response.raise_for_status()
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

def get_assets(ctd_ip, headers):
    """Fetches all assets from the CTD instance returning specific fields."""
    print("Querying assets from CTD...")
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
            asset_response = requests.get(asset_url, headers=headers, params=params, verify=False)
            asset_response.raise_for_status()
            asset_data = asset_response.json()
            
            objects = asset_data.get("objects", [])
            raw_assets.extend(objects)
            
            if len(objects) < asset_per_page:
                break
                
            asset_page += 1
            
        except Exception as e:
            print(f"Failed to fetch assets on page {asset_page}: {e}")
            sys.exit(1)
            
    print(f"Total raw assets pulled: {len(raw_assets)}")
    return raw_assets

def parse_assets(raw_assets):
    """Parses the raw assets, filtering for those with non-null edge_ids."""
    print("Parsing assets for active edge_ids...")
    
    # Optimized list comprehension to filter out null edge_ids and map the required fields
    edge_assets = [
        {
            'id': a.get('id'),
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

# Main Orchestration
def main():
    print("=== Claroty CTD Edge Asset Extractor ===")
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()

    # 1. Authenticate
    headers = authenticate(ctd_ip, username, password)

    # 2. Get Assets
    raw_assets = get_assets(ctd_ip, headers)

    # 3. Parse Assets
    edge_assets = parse_assets(raw_assets)
    
    # 4. Terminal Output
    if not edge_assets:
        print("\nNo assets found matching the criteria (edge_id is not null).")
    else:
        print(f"\nFound {len(edge_assets)} Edge Assets:\n")
        # Format the output cleanly into columns
        print(f"{'Asset ID':<10} | {'Asset Name':<30} | {'Edge ID':<40} | {'OS':<20} | {'Subnet'}")
        print("-" * 130)
        
        for asset in edge_assets:
            a_id = str(asset['id'])
            a_name = str(asset['name'])
            e_id = str(asset['edge_id'])
            a_os = str(asset['os'])
            a_sub = str(asset['subnet'])
            
            print(f"{a_id:<10} | {a_name:<30} | {e_id:<40} | {a_os:<20} | {a_sub}")

if __name__ == "__main__":
    main()