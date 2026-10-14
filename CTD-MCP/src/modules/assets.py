import json
from typing import Any, Optional
from pydantic import Field, AnyUrl

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.fastmcp.resources import TextResource

from src.modules.base import BaseModule
from src.resources.assets import ASSETS_SCHEMA_URI, ASSETS_SCHEMA_DOCS

class AssetsModule(BaseModule):
    """
    Unified interface for querying and analyzing network assets via Claroty CTD V1 REST endpoints.

    Provides core mechanisms for bulk asset discovery (`search_assets`) and isolated, field-level 
    metadata extraction (`get_asset_details`). Use this module to perform network posture assessments, 
    validate asset identifiers, and retrieve structural profiles (identity, network config, 
    and vulnerability/risk state) from target network environments.
    """

    def register_tools(self, server: FastMCP) -> None:
        super().register_tools(server)

        self._add_tool(
                server=server, 
                method=self.get_assets_schema, 
                name="get_assets_schema",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

        self._add_tool(
                server=server, 
                method=self.search_assets, 
                name="search_assets",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )        
        self._add_tool(
                server=server, 
                method=self.get_asset_details, 
                name="get_asset_details",
                annotations=ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                )
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register the Assets schema resources with the MCP Server."""
        super().register_resources(server)

        
        resource = TextResource(
            uri=AnyUrl(ASSETS_SCHEMA_URI),
            name="ctd_assets_schema",
            description="Contains the master guide, allowed filters, and enums for the `search_assets` and `get_assets_details` tools.",
            text=ASSETS_SCHEMA_DOCS, 
            mime_type="text/markdown"
        )
        
        self._add_resource(server, resource)

        
    #TOOL FOR ASSETS SCHEMA
    def get_assets_schema(self) -> str:
        """Retrieves the complete Claroty CTD Assets Search Schema, Filter Keys, and Guide.
        
        Call this tool BEFORE executing search_assets to look up 
        allowed filter keys, required data types, integer enum mappings, or return fields.
        """
        return ASSETS_SCHEMA_DOCS

    def search_assets(
            self,
            filters: dict[str, str | int | bool | list[str | int]] | None = Field(                
                default=None,
                #description="Dictionary of search filters. Consult resource://ctd/assets-schema for allowed filter keys, data types, and enum mappings.",
                description="Dictionary of search filters. Call the `get_assets_schema` tool to find allowed filter keys, data types, and enum mappings.",
                examples=[{"vendor__icontains": "Rockwell", "risk_level__exact": 3}],
            ),
            fields: list[str] = Field(
                default=["id", "name", "ipv4", "ipv6", "mac", "vendor", "model", "firmware", "asset_type", "risk_level"],
                #description="List of requested asset fields. Consult resource://ctd/assets-schema for available fields. Defaults to a standard set of identity and network fields if omitted.",
                description="List of requested asset fields. Call the `get_common_schema` tool for available fields. Defaults to a standard set of identity and network fields if omitted.",
                examples=[["id", "hostname", "ipv4", "vulnerabilities"]],
            ),
            limit: int | None = Field(
                default=None,
                ge=1,
                le=500,
                description="Maximum number of assets to return. If omitted, all matching assets are retrieved via auto-pagination.",
            ),
        ) -> str:
            """Find network assets by specified criteria and return their details.

            Use this tool to discover assets based on identity, location, risk score, 
            or hardware classification. Call the `get_assets_schema` tool before 
            constructing filter expressions to ensure correct data types and integer 
            enum values. Call `get_common_schema` tool for specific return fields.
            """
            try:
                # Input Validation 
                clean_fields = [str(f).strip() for f in fields if str(f).strip()]
                if not clean_fields:
                    clean_fields = ["id", "name", "ipv4", "mac", "asset_type"] # Default fallback

                # Base default parameters
                params: dict[str, Any] = {
                    'special_hint__exact': 0,  # Default to unicast
                    'valid__exact': True,      # Default to valid assets
                    'ghost__exact': False,     # Default to non-ghost assets
                    'approved__exact': True,   # Default to approved assets
                    'fields': ",;$".join(clean_fields)
                }

                # Apply LLM filters
                if filters:
                    for key, value in filters.items(): 
                        if isinstance(value, list):
                            params[key] = ",;$".join(str(v).strip() for v in value)
                        else:
                            params[key] = value

                # Pagination
                all_objects = []
                current_page = 1
                
                # Chunking
                per_page = min(limit, 500) if limit is not None else 500
                params['per_page'] = per_page

                while True:
                    params['page'] = current_page
                    
                    # Fetch from V1 endpoint
                    response_data = self.client.request("GET", "/ranger/assets", params=params)
                    objects = response_data.get('objects', [])
                    
                    if not objects:
                        break
                        
                    all_objects.extend(objects)

                    # Stop Conditions:
                    # Hit or exceeded the requested limit:
                    if limit is not None and len(all_objects) >= limit:
                        all_objects = all_objects[:limit] # Truncate to exact requested limit
                        break
                    
                    # Reached the end of the database:
                    if len(objects) < per_page:
                        break
                        
                    current_page += 1

                if not all_objects:
                    return "No assets found matching the specified criteria."

                # Output Token Optimization
                # Strip key-value pairs where the value is None, "", or []
                optimized_objects = []
                for obj in all_objects:
                    cleaned_obj = {k: v for k, v in obj.items() if v not in (None, "", [], {})}
                    optimized_objects.append(cleaned_obj)

                # Clean JSON serialization, remove all unnecessary spaces and newlines
                return self._format_to_markdown(optimized_objects)

            except Exception as e:
                return f"Error searching assets: {str(e)}"

    def get_asset_details(
        self,
        asset_identifier: str | int = Field(
            description="The numerical asset ID (e.g., 179) or full resource ID with the site ID hyphenated to the asset ID. (e.g., '179-1').",
            examples=["179-1", "402", 79]
        ),
        fields: list[str] = Field(
            default=["id", "name", "ipv4", "ipv6", "mac", "vendor", "model", "firmware", "asset_type", "risk_level"],
            #description="List of requested asset fields. Consult resource://ctd/assets-schema for available fields. Defaults to standard identity and network fields if omitted.",
            description="List of requested asset fields. Call the `get_common_schema` tool for available fields. Defaults to a standard set of identity and network fields if omitted.",
            examples=[["id", "hostname", "ipv4", "vulnerabilities"]]
        )
    ) -> str:
        """Retrieve the diagnostic profile of a specific network asset.

        Use this to query a single asset by its ID for its details. 
        Call the `get_common_schema` tool for available return fields. 
        Returns the full asset record including device details, network 
        configuration, and risk level.
        """
        try:
            # 1. Identifier Validation & Construction
            identifier_str = str(asset_identifier).strip()
            
            if not identifier_str:
                return "Error: Invalid asset identifier provided."
                
            # If the LLM passes a plain asset_id (no hyphen), assume site 1
            if "-" in identifier_str:
                final_resource_id = identifier_str
            else:
                final_resource_id = f"{identifier_str}-1"

            # 2. Field Validation
            clean_fields = [str(f).strip() for f in fields if str(f).strip()]
            if not clean_fields:
                clean_fields = ["id", "name", "ipv4", "mac", "asset_type"] # Default fallback

            params: dict[str, Any] = {
                'fields': ",;$".join(clean_fields)
            }

            # 3. Fetch from V1 endpoint
            response_data = self.client.request("GET", f"/ranger/assets/{final_resource_id}", params=params)

            if not response_data:
                return f"No asset found matching resource_id: {final_resource_id}"

            # 4. Output Token Optimization
            cleaned_obj = {k: v for k, v in response_data.items() if v not in (None, "", [], {})}

            # Clean JSON serialization
            return self._format_to_markdown(cleaned_obj)

        except Exception as e:
            return f"Error fetching details for asset {final_resource_id if 'final_resource_id' in locals() else 'Unknown'}: {str(e)}"