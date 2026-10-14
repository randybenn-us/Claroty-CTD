import json
import os
import sys
import requests
import urllib3
from dotenv import load_dotenv
from typing import Any, Dict, List, Optional

# Disable SSL warnings for internal network appliances
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CTDClient:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(current_dir)
        env_path = os.path.join(root_dir, '.env')
        
        load_dotenv(dotenv_path=env_path)
        self.host = os.getenv("CTD_HOST")
        self.username = os.getenv("CTD_USERNAME")
        self.password = os.getenv("CTD_PASSWORD")

        if not all([self.host, self.username, self.password]):
            raise ValueError("Missing CTD credentials in environment variables.")

        self.base_url = f"https://{self.host}"
        self.token = None

    def authenticate(self) -> dict:
        """Authenticates with CTD based on the /auth/authenticate spec."""
        url = f"{self.base_url}/auth/authenticate"

        payload = {"username": self.username, "password": self.password}
        headers = {'Content-type': 'application/json'}

        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        
        data = response.json()
        if "success" in data and data.get("success") is False:
            raise Exception(f"Authentication Failed: {data.get('error', 'Unknown error')}")
            
        self.token = data['token']
        return {'Authorization': self.token}

    def get_headers(self) -> dict:
        """Returns headers with an active token."""
        if not self.token:
            return self.authenticate()
        return {'Authorization': self.token}

    def request(self, method: str, endpoint: str, params: Optional[dict] = None) -> dict:
        """Helper to handle self-healing token retries automatically."""
        headers = self.get_headers()
        url = f"{self.base_url}{endpoint}"
        
        response = requests.request(
            method, 
            url, 
            headers=headers, 
            params=params,   
            verify=False)
        
        # Self-healing: if token expired, re-auth and try exactly once more
        if response.status_code == 401:
            headers = self.authenticate()
            response = requests.request(method, url, headers=headers, params=params, verify=False)
            
        response.raise_for_status()
        return response.json()