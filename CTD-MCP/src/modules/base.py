import json
from typing import Callable, Any
from mcp.server.fastmcp import FastMCP
from mcp.types import Resource, ToolAnnotations
from src.client import CTDClient

from src.resources.common import COMMON_SCHEMA_URI, COMMON_SCHEMA_DOCS

# Default Annotations for Read-Only Tools
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False, #CTD is closed
)

class BaseModule:
    #class-level flags shared across all module instances
    _common_tool_registered = False
    _common_resource_registered = False

    def __init__(self, client: CTDClient) -> None:
        """
        Initializes the base module with a shared Claroty CTD API client.
        """
        self.client = client
        self.tools: list[str] = []       # Tracks registered tool names
        self.resources: list[str] = []   # Tracks registered resource URIs

    def register_tools(self, server: FastMCP) -> None:
        """
        Registers shared base tools. 
        Child modules MUST call super().register_tools(server) when adding more tools.
        """
        if not BaseModule._common_tool_registered:
            self._add_tool(
                server=server,
                method=self.get_common_schema,
                name="get_common_schema",
                annotations=READ_ONLY_ANNOTATIONS
            )
            BaseModule._common_tool_registered = True

    def register_resources(self, server: FastMCP) -> None:
        """
        Registers shared base resources.
        Child modules should call super().register_resources(server) when overriding.
        """
        if not BaseModule._common_resource_registered:
            resource = Resource(
                uri=COMMON_SCHEMA_URI,
                name="CTD Common Schema",
                description="Shared enums and return fields used across multiple tools.",
                mime_type="text/markdown",
                text=COMMON_SCHEMA_DOCS
            )
            self._add_resource(server, resource)
            BaseModule._common_resource_registered = True

    def _add_tool(
        self, 
        server: FastMCP, 
        method: Callable[..., Any], 
        name: str,
        annotations: ToolAnnotations | None = None
    ) -> None:
        """Programmatically registers a class method as an MCP tool using add_tool."""
        prefixed_name = f"ctd_{name}"
        server.add_tool(
            method,
            name=prefixed_name,
            annotations=annotations or READ_ONLY_ANNOTATIONS,
            structured_output=False,
        )
        self.tools.append(prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        """
        Programmatically registers an MCP Resource object with the server.
        """
        server.add_resource(resource=resource)
        
        resource_uri = resource.uri
        self.resources.append(str(resource_uri))

    def get_common_schema(self) -> str:
        """Retrieve the shared schema containing common info across multiple tools (asset type IDs, return fields, and insight names)."""
        return COMMON_SCHEMA_DOCS

    @staticmethod
    def _format_to_markdown(data: Any) -> str:
        """
        Dynamically converts JSON-like data (dicts or lists of dicts) into clean Markdown.
        Agnostic to specific keys. Nested objects are safely stringified.
        """
        if not data:
            return "No data returned."

        # SCENARIO A: It's a list of dictionaries -> Build a Markdown Table
        if isinstance(data, list) and all(isinstance(i, dict) for i in data):
            if not data:
                return "Empty list."
            
            headers = []
            for item in data:
                for key in item.keys():
                    if key not in headers:
                        headers.append(key)
            
            header_row = "| " + " | ".join(str(h) for h in headers) + " |"
            separator = "|" + "|".join(["---"] * len(headers)) + "|"
            
            rows = []
            for item in data:
                row_vals = []
                for h in headers:
                    val = item.get(h, "")
                    if isinstance(val, (dict, list)):
                        val = f"`{json.dumps(val, separators=(',', ':'))}`"
                    
                    # Escape pipes and newlines so they don't break the markdown table format
                    safe_val = str(val).replace("|", "\\|").replace("\n", " ")
                    row_vals.append(safe_val)
                    
                rows.append("| " + " | ".join(row_vals) + " |")
                
            return "\n".join([header_row, separator] + rows)

        # SCENARIO B: It's a single dictionary -> Build a Bulleted List
        elif isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    formatted_val = f"`{json.dumps(value, separators=(',', ':'))}`"
                else:
                    formatted_val = str(value).replace("\n", " ")
                lines.append(f"- **{key}**: {formatted_val}")
            return "\n".join(lines)

        # SCENARIO C: It's a flat list of strings/numbers -> Build a simple list
        elif isinstance(data, list):
            return "\n".join(f"- {item}" for item in data)
            
        # SCENARIO D: Fallback for raw strings/ints
        else:
            return str(data)
            