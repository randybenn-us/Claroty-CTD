import csv
from itertools import count
import requests
import re
import time
import os
from dotenv import load_dotenv
from urllib.parse import quote

#CONFIGURATION
INPUT_CSV = input("Enter input CSV file name (format should be [program, vendor, version, in_ctd]): ").strip() 
OUTPUT_CSV = input("Enter CSV file name you want to save output to: ").strip() 
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'

load_dotenv()
API_KEY = os.getenv('NVD_KEY')
HEADERS = {}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

#RATE LIMITING (NVD api bottle neck, only 50 requests per 30 s)
SLEEP_DELAY = 0.6 

#RULES & OVERRIDES
#ordering matters, using re.search()
SUBSTRING_OVERRIDES = {
    # Blocked Vendors/Program names
    r"\bhp\b": "NOT_FOUND",
    r"\bhewlett packard\b": "NOT_FOUND",
    r"\bhewlett-packard\b": "NOT_FOUND",
    r"\buniversal crt\b": "NOT_FOUND",
    r"\bwinrt\b": "NOT_FOUND",

    # MS Suite, Dev Tools, SDKs
    r"\bmicrosoft 365 apps\b": "cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*",
    r"\bmicrosoft 365\b": "cpe:2.3:a:microsoft:365:*:*:*:*:*:*:*:*",
    r"\bmicrosoft edge webview\b": "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*",
    r"\bmicrosoft edge\b": "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
    r"\bmicrosoft teams\b": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:*:*:*",
    r"\bwindows software development kit\b": "cpe:2.3:a:microsoft:windows_software_development_kit:*:*:*:*:*:*:*:*",
    r"\bwindows sdk\b": "cpe:2.3:a:microsoft:windows_software_development_kit:*:*:*:*:*:*:*:*",

    # Browsers, Comms, Security
    r"\bgoogle chrome\b": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    r"\bmozilla firefox\b": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
    r"\bbrave\b": "cpe:2.3:a:brave:brave:*:*:*:*:*:*:*:*",
    r"\bwebex meetings server\b": "cpe:2.3:a:cisco:webex_meetings_server:*:*:*:*:*:*:*:*",
    r"\bwebex meetings\b": "cpe:2.3:a:cisco:webex_meetings:*:*:*:*:*:*:*:*",
    r"\bwebex\b": "cpe:2.3:a:cisco:webex:*:*:*:*:*:*:*:*",
    r"\bcrowdstrike\b": "cpe:2.3:a:crowdstrike:falcon:*:*:*:*:*:*:*:*",
    #r"\bdell supportassist\b": "cpe:2.3:a:dell:supportassist:*:*:*:*:*:*:*:*",
    #r"\blenovo vantage\b": "cpe:2.3:a:lenovo:vantage:*:*:*:*:*:*:*:*",
    #r"\bhp support assistant\b": "cpe:2.3:a:hp:support_assistant:*:*:*:*:*:*:*:*"

    # OEM, Hardware Util
    r"\bnvidia geforce experience\b": "cpe:2.3:a:nvidia:geforce_experience:*:*:*:*:*:*:*:*",
    r"\bnvidia control panel\b": "cpe:2.3:a:nvidia:control_panel:*:*:*:*:*:*:*:*",
    r"\bintel driver (?:&) support assistant\b": "cpe:2.3:a:intel:driver_\\&_support_assistant:*:*:*:*:*:*:*:*",
    r"\bintel proset.*?wireless\b": "cpe:2.3:a:intel:proset\\/wireless_wifi:*:*:*:*:*:*:*:*",
    r"\brealtek.*?audio\b": "cpe:2.3:a:realtek:high_definition_audio_driver:*:*:*:*:*:*:*:*",
    r"\bcorsair icue\b": "cpe:2.3:a:corsair:icue:*:*:*:*:*:*:*:*",
    r"\bamd software\b": "cpe:2.3:a:amd:radeon_software:*:*:*:*:*:*:*:*",

}


#PRE-COMPILED REGEX
ALLOWED_JUNK_PATTERN = re.compile(
    r'\b\d+(?:\.\d+)+\b|'                
    r'\b\d+\b|'                          
    r'\(?\b(x86_64|x64_86|amd64|arm64|x64|x86|x32|win32|win64|64-?bit|32-?bit|all users|user)\b\)?|' 
    r'\b(v|version|desktop|client|server|for|windows|mac|linux|edition|app|software|release|redistributable|update|installer|service|pack|package)\b|'                  
    r'[_\-\.\(\)\s]+',
    re.IGNORECASE
)

#FUNCTIONS
def clean_program_name(name):

    name = name.split(' - ')[0]    
    name = re.sub(r'(?i)\b[a-z]{2}-[a-z]{2}\b', '', name) 

    arch_pattern = r'(?i)\b(x86_64|x64_86|amd64|arm64|x64|x86|x32|win32|win64|64-?bit|32-?bit|all users|user)\b'
    name = re.sub(arch_pattern, '', name)
    
    version_pattern = r'\b\d+(?:\.\d+)+\b'
    name = re.sub(version_pattern, '', name)

    name = re.sub(r'\(\s*\)', '', name)
    cleaned_name = re.sub(r'\s+', ' ', name).strip()
    cleaned_name = re.sub(r'^-|-$', '', cleaned_name).strip()
    
    return cleaned_name

def is_valid_title_match(keyword, nvd_title):
    nvd_title = re.split(r'\s+[-–—]\s+', nvd_title, maxsplit=1)[0].strip()
    keyword_lower = keyword.lower()
    title_lower = nvd_title.lower()
    remainder = ""

    if keyword_lower in title_lower: #direction 1: keyword in title
        parts = title_lower.split(keyword_lower, 1)
        remainder = parts[0] + " " + parts[1]
    elif title_lower in keyword_lower: #direction 2: title in keyword
        parts = keyword_lower.split(title_lower, 1)
        remainder = parts[0] + " " + parts[1]
    else:
        return False
        
    remainder = ALLOWED_JUNK_PATTERN.sub('', remainder)
    return len(remainder) == 0

def generalize_cpe(raw_cpe):
    parts = raw_cpe.split(':')
    if len(parts) >= 5 and parts[0] == 'cpe' and parts[1] == '2.3':
        base_cpe = ':'.join(parts[:5])
        return f"{base_cpe}:*:*:*:*:*:*:*:*"
    return raw_cpe

def query_nvd_for_cpe(keyword, is_retry=False):
    """
    Queries the API, applying Tier 1 and Tier 2 matching.
    If the API returns 0 results, it dynamically strips trailing filler words 
    (like 'desktop' or 'client') and tries one more time.
    Returns: (cpe_string, match_confidence)
    """
    if not keyword:
            return None, "N" 
        
    keyword_lower = keyword.lower()

    #check overrides
    for pattern, cpe in SUBSTRING_OVERRIDES.items():
        if re.search(pattern, keyword_lower):
            if cpe == "NOT_FOUND":
                if not is_retry: print("[Override Applied: NOT_FOUND]", end=" ")
                return None, "N"
            if not is_retry: print("[Override Applied]", end=" ")
            return cpe, "O"

    #api query
    encoded_keyword = quote(keyword)
    url = f"{NVD_API_URL}?keywordSearch={encoded_keyword}"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status() 
        data = response.json()
        
        valid_windows_products = []
        if data.get('totalResults', 0) > 0 and 'products' in data:
            raw_products = data['products']
            
            #pre-filter for ('a') in cpe part and ('windows') in target_sw
            for product in raw_products:
                cpe_string = product.get('cpe', {}).get('cpeName', '')
                parts = cpe_string.split(':')
                
                if len(parts) < 3 or parts[2] != 'a':
                    continue
                
                if len(parts) >= 13:
                    target_sw = parts[10].lower()
                    if target_sw in ['*', '-'] or 'windows' in target_sw:
                        valid_windows_products.append(product)
                else:
                    valid_windows_products.append(product)
            
        #fallback: retry after stripping trailing filler words if no configs returned
        if not valid_windows_products:
            if not is_retry:
                retry_pattern = r'(?i)(?:\s+|-|_)*(?:desktop|client|server|edition|agent|app|windows|mac|linux|v|version|for|software|release|\d+(?:\.\d+)*)+\s*$'
                retry_keyword = re.sub(retry_pattern, '', keyword).strip()
                
                if retry_keyword != keyword:
                    print(f"[0 Results. Retrying as '{retry_keyword}']", end=" ")
                    time.sleep(SLEEP_DELAY) 
                    return query_nvd_for_cpe(retry_keyword, is_retry=True)
            
            return None, "N"
            
        #check returned configurations for matches
        kw_tokens = keyword_lower.split()
        potential_match = None
        
        for product in valid_windows_products:
            cpe_data = product['cpe']
            cpe_string = generalize_cpe(cpe_data['cpeName'])
            
            for title_info in cpe_data.get('titles', []):
                title = title_info.get('title', '')
                
                #1. strict substring match
                if is_valid_title_match(keyword, title):
                    return cpe_string, "F"
                
                #2. fallback: token match
                if not potential_match:
                    title_lower = title.lower()
                    title_tokens = title_lower.split()
                    
                    if all(token in title_tokens for token in kw_tokens):
                        potential_match = cpe_string 

        if potential_match:
            print("[Token Fallback Match]", end=" ")
            return potential_match, "P"

        return None, "N"
            
    except requests.exceptions.HTTPError as e:
        print(f" [!] Blocked by NVD: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f" [!] Network Error: {e}")

    return None, "N"

def main():
    start_time = time.time()
    
    #output csv
    with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(['program', 'vendor', 'version', 'in_ctd', 'cleaned_name', 'cpe_name', 'confidence'])

    print("Starting NVD CPE enumeration...")
    
    with open(INPUT_CSV, mode='r', encoding='utf-8-sig') as in_file:
        reader = csv.DictReader(in_file)
        
        if not reader.fieldnames or 'program' not in [h.strip().lower() for h in reader.fieldnames if h]:
            print("\n[ERROR] Could not find a column named 'program' in your CSV.")
            return

        rows = list(reader)
        max_rows = len(rows)
        print(f"Found {max_rows} rows in {INPUT_CSV}.\n")
    
        for count, row in enumerate(rows, start=1):
                
            raw_program = ""
            raw_vendor = ""
            raw_version = ""
            raw_in_ctd = ""
            
            for key in row.keys():
                clean_key = key.strip().lower() if key else ""
                if clean_key == 'program':
                    raw_program = row[key]
                elif clean_key == 'vendor':
                    raw_vendor = row[key]
                elif clean_key == 'version':
                    raw_version = row[key]
                elif clean_key == 'in_ctd':
                    raw_in_ctd = row[key]
            
            if not raw_program:
                continue
                
            cleaned_name = clean_program_name(raw_program)
            
            print(f"[{count}/{max_rows}] Searching: {cleaned_name} ...", end=" ")            

            cpe_name, confidence_flag = query_nvd_for_cpe(cleaned_name)
            
            #write API results
            with open(OUTPUT_CSV, mode='a', newline='', encoding='utf-8') as out_file:
                writer = csv.writer(out_file)
                if cpe_name:
                    writer.writerow([raw_program, raw_vendor, raw_version, raw_in_ctd, cleaned_name, cpe_name, confidence_flag])
                    print(f"Found Base: {cpe_name} (Confidence: {confidence_flag})")
                else:
                    writer.writerow([raw_program, raw_vendor, raw_version, raw_in_ctd, cleaned_name, 'NOT_FOUND', 'N'])
                    print("NOT FOUND")
            
            time.sleep(SLEEP_DELAY)

    #print results   
    print("\nProcess complete. Results saved to", OUTPUT_CSV)

    #print time
    end_time = time.time()
    total_seconds = end_time - start_time
    minutes, seconds = divmod(total_seconds, 60)
    print(f"Total Execution Time: {int(minutes)} minutes and {seconds:.2f} seconds")

if __name__ == "__main__":
    main()