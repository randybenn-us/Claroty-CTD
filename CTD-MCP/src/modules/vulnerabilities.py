import json
from pydantic import Field
from typing import Optional
from mcp.server.fastmcp import FastMCP
from src.modules.base import BaseModule

class VulnerabilitiesModule(BaseModule):
    """Handles CVE lookups, asset-to-vulnerability mapping, and threat intelligence."""

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(server, self.search_vulnerabilities, "search_vulnerabilities")
        self._add_tool(server, self.get_vulnerability_details, "get_vulnerability_details")
        self._add_tool(server, self.search_asset_vulnerabilities, "search_asset_vulnerabilities")

    def search_vulnerabilities(
        self,
        actively_exploited: Optional[bool] = Field(default=None, description="Filter to only show actively exploited CVEs (True/False)."),
        cve_id: Optional[str] = Field(default=None, description="Search for a specific CVE by its ID (e.g., 'CVE-2023-4368').")
    ) -> str:
        """
        Retrieves a high-level list of Vulnerabilities (CVEs) present in the environment.
        Use this to answer "List all CVEs" or to check if a specific CVE exists globally.
        """
        try:
            params = {'per_page': 100}
            if actively_exploited is not None:
                params['actively_exploited__exact'] = actively_exploited
            
            # Note: The API spec for the list endpoint doesn't natively filter by cve_id__exact,
            # but we can fetch the list and filter locally if requested to save LLM context.
            data = self.client.request("GET", "/ranger/vulnerabilities", params=params)
            objects = data.get('objects', [])
            
            if not objects:
                return "No vulnerabilities found matching those criteria."

            if cve_id:
                objects = [obj for obj in objects if obj.get("cve_id") == cve_id]

            # Flatten to save tokens
            clean_cves = []
            for vuln in objects:
                clean_cves.append({
                    "resource_id": vuln.get("resource_id"),
                    "cve_id": vuln.get("cve_id"),
                    "cvss_v3": vuln.get("cvss_v3_score", {}).get("value"),
                    "severity": vuln.get("cvss_v3_score", {}).get("label"),
                    "epss_score": vuln.get("epss_score", {}).get("value"),
                    "actively_exploited": vuln.get("actively_exploited"),
                    "total_affected_assets": vuln.get("assets_count", {}).get("total_affected_assets_count"),
                    "description": vuln.get("description")
                })

            return json.dumps(clean_cves, indent=2)
            
        except Exception as e:
            return f"Error searching vulnerabilities: {str(e)}"

    def search_asset_vulnerabilities(
        self,
        cve_id: Optional[str] = Field(default=None, description="Exact CVE ID to find all affected assets (e.g., 'CVE-2020-6088')."),
        asset_id: Optional[str] = Field(default=None, description="Exact Asset ID to find all CVEs on that asset (e.g., '11')."),
        actively_exploited: Optional[bool] = Field(default=None, description="Filter for matches that are actively exploited.")
    ) -> str:
        """
        Retrieves matches between Assets and Vulnerabilities. 
        CRITICAL: Use this to answer "List all CVEs for asset xxxx" or "List all assets affected by CVE xxxx".
        """
        try:
            params = {'per_page': 100}
            
            # Map human-readable inputs to the exact API query parameters
            if cve_id: params['cve_id__exact'] = cve_id
            if asset_id: params['asset_id__exact'] = asset_id
            if actively_exploited is not None: params['actively_exploited__exact'] = actively_exploited

            data = self.client.request("GET", "/ranger/asset-vulnerabilities", params=params)
            objects = data.get('objects', [])
            
            if not objects:
                return "No asset-vulnerability matches found for those criteria."

            # Flatten 
            matches = []
            for match in objects:
                matches.append({
                    "match_resource_id": match.get("resource_id"),
                    "asset_id": match.get("asset_id"),
                    "asset_name": match.get("asset_name"),
                    "ipv4": match.get("ipv4", [None])[0] if match.get("ipv4") else None,
                    "cve_id": match.get("cve_id"),
                    "cvss_v3": match.get("cvss_v3_score", {}).get("value"),
                    "relevance": match.get("relevance__"),
                    "status": match.get("status__")
                })

            return json.dumps(matches, indent=2)
            
        except Exception as e:
            return f"Error searching asset vulnerabilities: {str(e)}"

    def get_vulnerability_details(
        self, 
        resource_id: str = Field(description="The exact 'resource_id' of the vulnerability (e.g., '1-1').")
    ) -> str:
        """
        Retrieves the complete, raw diagnostic profile of a single vulnerability.
        Use this when a deep-dive into a specific CVE's metadata or patch status is requested.
        """
        try:
            data = self.client.request("GET", f"/ranger/vulnerabilities/{resource_id}")
            return json.dumps(data, indent=2)
        except Exception as e:
            return f"Error fetching details for vulnerability {resource_id}: {str(e)}"