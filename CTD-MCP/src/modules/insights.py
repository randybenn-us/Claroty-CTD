import json
import re
from typing import Any, Optional
from pydantic import Field, AnyUrl
import urllib.parse

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.insights import INSIGHTS_SCHEMA_URI, INSIGHTS_SCHEMA_DOCS


class InsightsModule(BaseModule):
    """
    Interface for retrieving automated operational and security insights from Claroty CTD.
    
    Provides access to holistic network risk assessments, pinpointing vulnerable assets, 
    risky network configurations, and critical communication patterns (e.g., external 
    connections, unsecured protocols, and PLC manipulations) across the industrial network.
    """

    def register_tools(self, server: FastMCP) -> None:  
        super().register_tools(server)

        """Registers the Insights tools with the MCP Server."""
        
        self._add_tool(
                server=server, 
                method=self.get_insights_schema, 
                name="get_insights_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )
        
        self._add_tool(
            server=server,
            method=self.search_insights,
             name= "search_insights",
             annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

        self._add_tool(
            server=server,
            method=self.get_insight_details,
             name= "get_insight_details",
             annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

        self._add_tool(
            server=server,
            method=self.filter_assets_by_insight_key,
            name= "filter_assets_by_insight_key",
            annotations=ToolAnnotations(
                 readOnlyHint=True,
                 destructiveHint=False,
                 idempotentHint=True,
                 openWorldHint=False,
             )
        )

    #register resources
    def register_resources(self, server: FastMCP) -> None:
        """Register the static Insights schema resources with the MCP Server."""
        super().register_resources(server)
        
        resource = TextResource(
            uri=AnyUrl(INSIGHTS_SCHEMA_URI),
            name="ctd_insights_schema",
            description="Contains the master guide, allowed filters, and enums for the `search_insights` tools",
            text=INSIGHTS_SCHEMA_DOCS, 
            mime_type="text/markdown"
        )
        
        self._add_resource(server, resource)

    #def for calling resource for insight schema
    def get_insights_schema(self) -> str:
        """Retrieves the complete Claroty CTD Insights Search Schema, Filter Keys, and Guide.
        
        Call this tool BEFORE executing search_insights if to look up 
        allowed filter keys, required data types, or integer enum mappings.
        """
        return INSIGHTS_SCHEMA_DOCS


    def search_insights(
        self,
        filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
            default=None,
            description="Dictionary of search filters. Call `get_insights_schema` for valid filter keys and `get_common_schema` for exact insight names and asset type IDs.",
            examples=[{"insight_name__exact": "Unsecured Protocols", "criticality__exact": [1, 2]}]
        )
    ) -> str:
        """Retrieve aggregated network insights, risky assets, and vulnerability summaries.

        Use this tool to discover high-level security warnings and operational 
        insights detected by CTD.
        """
        try:
            # 1. Base Default Parameters
            params: dict[str, Any] = {
                'page': 1,
                'per_page': 50,
                'format': 'insight_page',
                'sort': '-risk_level',
                'site_id__exact': 1,
                'ghost__exact': False,
                'special_hint__exact': 0,
                'insight_status__exact': 0,
            }
            
            # 3. Apply LLM Filters & Handle Arrays
            if filters:
                for key, value in filters.items():
                    if isinstance(value, list):
                        params[key] = ",;$".join(str(v).strip() for v in value)
                    else:
                        params[key] = value

            # 4. Fetch from Endpoint
            response_data = self.client.request("GET", "/ranger/insights_summary", params=params)
            
            # Handle potential wrapper (e.g., if inside an 'objects' key like Assets)
            if isinstance(response_data, dict) and "objects" in response_data:
                objects = response_data.get("objects", [])
            elif isinstance(response_data, list):
                objects = response_data
            else:
                return "Error: Unexpected response format from the insights API."

            if not objects:
                return "No insights found matching the specified criteria."

            # 5. Output Token Optimization
            keys_to_drop = {"headers", "default_sort", "other_side_headers", "other_side_default_sort"}
            optimized_objects = []

            for obj in objects:
                cleaned_obj = {}
                for k, v in obj.items():
                    # Strip out UI-specific keys and empty values
                    if k in keys_to_drop or v in (None, "", [], {}):
                        continue
                    
                    # Clean Claroty's proprietary UI syntax and HTML tags from strings
                    if isinstance(v, str):
                        # Fix Claroty Links: [[14 assets$$/...]] -> 14 assets
                        v = re.sub(r'\[\[(.*?)\$\$.*?\]\]', r'\1', v)
                        # Strip all HTML tags (<br>, <strong>, etc.)
                        v = re.sub(r'<[^>]+>', ' ', v)
                        # Clean up any extra spacing left behind
                        v = re.sub(r'\s+', ' ', v).strip()
                        
                    cleaned_obj[k] = v
                    
                optimized_objects.append(cleaned_obj)

            # 5. Format to clean Markdown Table
            return self._format_to_markdown(optimized_objects)

        except Exception as e:
            return f"Error searching insights: {str(e)}"
    
    #add tools for specific insights
    def get_insight_details(
            self,
            insight_name: str = Field(
                description="Specific insight name to filter by. Accepts a single string. Call `get_common_schema` tool for allowed insight names.",
                examples=["Unsecured Protocols", "Windows CVEs"]
            )
        ) -> str:
            """Retrieve all assets and details for a specific insight.

            Returns a Markdown table of affected assets and insight context. Each row 
            includes a `Filter Key` to be used with the `filter_assets_by_insight` 
            tool for deeper investigation. Call `get_common_schema` first for valid 
            insight names.
            """
                
            try:
                insight_path = urllib.parse.quote(insight_name.strip())
                
                all_rows = []
                current_page = 1
                per_page = 50
                
                metadata = {"description": "", "total_records": 0}
                valid_headers = []
                valid_indices = []

                while True:
                    params = {
                        'format': 'insight_page',
                        'page': current_page,
                        'per_page': per_page,
                        'ghost__exact': False,
                        'special_hint__exact': 0,
                        'site_id__exact': 1,
                        'insight_status__exact': 0,
                    }

                    response_data = self.client.request("GET", f"/ranger/insight_details/{insight_path}", params=params)

                    if not response_data or not isinstance(response_data, dict):
                        break

                    page_rows = response_data.get("rows", [])
                    
                    # Extract headers and metadata on the first page
                    if current_page == 1:
                        raw_desc = response_data.get("description", "")
                        metadata["description"] = raw_desc.replace("<br>", " ").replace("<strong>", "").replace("</strong>", "")
                        metadata["total_records"] = response_data.get("count_total", 0)
                        
                        for h in response_data.get("headers", []):
                            # Drop the "Actions" column
                            if h.get("type") != "bulk_actions" and h.get("name", "").lower() != "actions":
                                valid_headers.append(h.get("name"))
                                valid_indices.append(h.get("header_num"))

                    if not page_rows:
                        break

                    all_rows.extend(page_rows)

                    # Stop Condition: Reached the end of available server data
                    if len(page_rows) < per_page:
                        break
                        
                    current_page += 1

                if not all_rows:
                    return f"No detail records found for insight '{insight_name}'."

                # Construct Markdown Output
                md_lines = [
                    f"### Insight: {insight_name}",
                    f"**Description:** {metadata['description']}",
                    f"**Total Records:** {metadata['total_records']}",
                    ""
                ]

                # Append the Filter Key column for LLM context
                table_headers = valid_headers + ["filter_key (Asset Lookup)"]
                
                # Build Table Header Row
                md_lines.append("| " + " | ".join(table_headers) + " |")
                md_lines.append("|" + "|".join(["---"] * len(table_headers)) + "|")

                # Build Table Rows
                for row in all_rows:
                    cells = row.get("cells", [])
                    row_data = []
                    
                    # Match cells to the valid indices
                    for idx in valid_indices:
                        if idx < len(cells):
                            # Clean cell text to prevent Markdown table breaks
                            cell_text = str(cells[idx]).replace("|", "\\|").replace("\n", " ")
                            row_data.append(cell_text)
                        else:
                            row_data.append("")
                    
                    filter_key = row.get("row_filter", {}).get("filter_key", "")
                    
                    if filter_key:
                        # The backticks force the LLM to treat it as a literal string
                        formatted_key = f"`{filter_key}`"
                    else:
                        formatted_key = ""
                        
                    row_data.append(formatted_key.replace("|", "\\|"))
                    
                    md_lines.append("| " + " | ".join(row_data) + " |")

                return "\n".join(md_lines)

            except Exception as e:
                return f"Error fetching details for insight '{insight_name}': {str(e)}"


    def filter_assets_by_insight_key(
            self,
            filter_key: str = Field(
                description="Use the exact string inside the backticks from `get_insight_details` to drill down into assets for a specific insight sub-category. Copy verbatim—do not alter, decode, or add spaces. Query strictly one key per message.",
                examples=["Unsecured Protocols,;$1,;$,;$SMB,;$SMB+version+1+is..."]
            ),
            fields: list[str] = Field(
                default=["id", "name", "ipv4", "vendor", "asset_type"],
                description="List of requested asset fields. Call the `get_common_schema` tool for available fields. Defaults to a standard set of identity and network fields if omitted.",
                examples=[["id", "hostname", "ipv4", "os", "risk_level"]]
            ),
            limit: int | None = Field(
                default=None,
                ge=1,
                le=500,
                description="Maximum number of assets to return. If omitted, all matching assets are retrieved via auto-pagination."
            )
        ) -> str:
            """Retrieve assets associated with a specific insight sub-category using a row key.

            Use this tool to drill down into a `filter_key` returned by `get_insight_details`. 
            Do not use this tool for broad searches by insight name. Query one key at a time.
            """

            if not filter_key:
                return "Error: 'filter_key' is strictly required."

            try:
                # Input Validation for fields
                clean_fields = [str(f).strip() for f in fields if str(f).strip()]
                if not clean_fields:
                    clean_fields = ["id", "name", "ipv4", "mac", "asset_type"] # Default fallback

                # Base default parameters for the assets endpoint
                params: dict[str, Any] = {
                    'special_hint__exact': 0,  
                    'valid__exact': True,      
                    'ghost__exact': False,     
                    'approved__exact': True,
                    'fields': ",;$".join(clean_fields),
                    'insight_row_key__exact': filter_key.strip()
                }

                all_objects = []
                current_page = 1
                
                # Chunking matching search_assets behavior
                per_page = min(limit, 500) if limit is not None else 500

                while True:
                    params['page'] = current_page
                    params['per_page'] = per_page

                    # Fetch from V1 Assets endpoint
                    response_data = self.client.request("GET", "/ranger/assets", params=params)
                    
                    if not isinstance(response_data, dict):
                        break

                    objects = response_data.get('objects', [])
                    if not objects:
                        break

                    all_objects.extend(objects)

                    # Stop Conditions
                    if limit is not None and len(all_objects) >= limit:
                        all_objects = all_objects[:limit] # Truncate to exact requested limit
                        break
                    
                    if len(objects) < per_page:
                        break
                        
                    current_page += 1

                if not all_objects:
                    return f"No assets found matching the filter key: '{filter_key}'."

                # Output Token Optimization
                optimized_objects = []
                for obj in all_objects:
                    # Strip out null, empty string, or empty list values
                    cleaned_obj = {k: v for k, v in obj.items() if v not in (None, "", [], {})}
                    optimized_objects.append(cleaned_obj)

                return self._format_to_markdown(optimized_objects)

            except Exception as e:
                return f"Error filtering assets by insight key: {str(e)}"
      