# src/resources/insights.py

INSIGHTS_SCHEMA_URI = "resource://ctd/insights-schema"
    
INSIGHTS_SCHEMA_DOCS = """# CTD Insights Search Schema and Guide

This document provides the allowed fields and filters for the `search_insights` tool.
**IMPORTANT ROUTING:** For Asset Type IDs and Exact Insight Names, you MUST call the `get_common_schema` tool.

## 1. Default Parameters 
Do not pass these unless overriding default behavior:
* `site_id__exact`: `1`
* `ghost__exact`: `false` (Excludes ghost/receive-only assets)
* `special_hint__exact`: `0` (Defaults to unicast. Enums: 0=unicast, 1=broadcast, 2=multicast, 3=out of scope, 4=external)
* `insight_status__exact`: `0` (Defaults to Open insights. Enums: 0=Open, 1=Hidden, 2=Completed)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary. Match the data types exactly.
For any filter marked with **Enums**, pass a single value or an array of multiple values to perform an "OR" search.

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `insight_name__exact` | String | Filter by exact insight name. *(Call `get_common_schema` for Insight Name Enums)* | `"Windows CVEs"` |
| `insight_status__exact` | Integer | Status of the insight. **Enums:** `0` (Open), `1` (Hidden), `2` (Completed). | `0` |
| `insight_severity__exact` | Integer | Severity of the insight. **Enums:** `0` (Low), `1` (Medium), `2` (High). | `1` |
| `asset_type__exact` | Integer | Asset classification ID. *(Call `get_common_schema` for Enums)* | `12` |
| `vendor__icontains` | String | Partial or full hardware vendor name match. | `"Rockwell"` |
| `protocol__exact` | String | Exact network protocol match. | `"Modbus"` |
| `criticality__exact` | Integer | Asset operational criticality. **Enums:** `0` (eLow), `1` (eMedium), `2` (eHigh). | `[1, 2]` |
| `class_type__exact` | Integer | Asset class ID. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |
"""