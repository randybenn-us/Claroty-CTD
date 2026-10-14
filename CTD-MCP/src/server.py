import sys
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient
from src.modules.assets import AssetsModule
from src.modules.vulnerabilities import VulnerabilitiesModule
from src.modules.insights import InsightsModule


# Initialize the FastMCP Server
# edit for when running local
mcp = FastMCP("Claroty CTD MCP Server")

def main():
    try:
        # Initialize the API Client
        client = CTDClient()

        # Instantiate Modules
        # APPEND TO LIST WITH NEW MODULES AS THEY ARE CREATED!!!
        modules = [
            AssetsModule(client=client),
            #VulnerabilitiesModule(client=client), 
            InsightsModule(client=client)
        ]

        # loop through all active modules and connect tools into FastMCP
        for module in modules:
            module.register_tools(mcp)
            module.register_resources(mcp)

        # FastMCP defaults to standard input/output (stdio) transport, (required for CLI tools)
        mcp.run()

        # Start server via HTTP for Web UIs, for later integration with OpenWeb UI
        #mcp.run(transport='sse')
        
    except ValueError as e:
        sys.stderr.write(f"Configuration Error: {e}\n")
    except Exception as e:
        sys.stderr.write(f"Failed to start MCP server: {e}\n")

if __name__ == "__main__":
    main()