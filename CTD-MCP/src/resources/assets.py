# src/resources/assets.py

ASSETS_SCHEMA_URI = "resource://ctd/assets-schema"
    
ASSETS_SCHEMA_DOCS = """# CTD Assets Search Schema and Guide

This document provides the specific filters for the `search_assets` tool. 
**IMPORTANT ROUTING:** For Allowed Return Fields, Asset Type IDs, and Insight Names, you MUST call the `get_common_schema` tool.

## 1. Default Parameters
Unless otherwise specified by the user, the tool automatically applies these default search filters. Do not pass these unless overriding default behavior:
* `ghost__exact`: `false` (Excludes ghost/receive-only assets)
* `valid__exact`: `true` (Only returns valid assets)
* `approved__exact`: `true` (Only returns approved assets)
* `special_hint__exact`: `0` (Defaults to unicast. Enums: 0=unicast, 1=broadcast, 2=multicast, 3=out of scope, 4=external)

---

## 2. Allowed Search Filters
Use these keys in the `filters` dictionary. Match the data types exactly.
For any filter marked with **Enums**, pass a single value or an array of multiple values to perform an "OR" search (e.g., `"purdue_level__exact": ["1", "1.5", "2"]`).

| Filter Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `ipv4__exact` | String | Exact IPv4 address. | `"192.168.1.50"` |
| `ipv6__exact` | String | Exact IPv6 address. | `"2001:0db8:85a3::8a2e:0370:7334"` |
| `mac__icontains` | String | Partial or full MAC address. | `"00:1A:2B"` or `"00:1A:2B:3C:4D:5E"` |
| `vlan__exact` | String | Exact VLAN identifier. | `"100"` |
| `asset_type__exact` | Integer | Specific asset classification ID. *(Call `get_common_schema` for Asset Type Enums)* | `12` |
| `class_type__exact` | Integer | Asset class ID. **Enums:** `0` (OT), `1` (IT), `2` (IoT). | `0` |
| `display_name__icontains` | String | Matches asset name, hostname, or display name. | `"Engineering Workstation"` |
| `os__exact` | String | Exact operating system name. | `"Windows 10"` |
| `model__icontains` | String | Hardware model name. | `"ControlLogix"` |
| `vendor__icontains` | String | Hardware vendor name. | `"Rockwell"` |
| `firmware__exact` | String | Exact firmware version. | `"v20.011"` |
| `serial__exact` | String | Exact hardware serial number. | `"SN-12345678"` |
| `protocol__exact` | String | Network protocol used. | `"Modbus"` |
| `relevance__exact`| Integer | Asset vulnerability relevance. **Enums:** `0` (Potentially Relevant), `1` (Confirmed). | `1` |
| `risk_level__exact` | Integer | CTD calculated risk for asset. **Enums:** `0` (Low), `1` (Medium), `2` (High), `3` (Critical). | `3` |
| `criticality__exact` | Integer | Operational criticality. **Enums:** `0` (eLow), `1` (eMedium), `2` (eHigh). | `2` |
| `purdue_level__exact`| String | Purdue model level. **Enums:** `"0"`, `"1"`, `"1.5"`, `"2"`, `"2.5"`, `"3"`, `"3.5"`, `"4"`, `"5"`, `"6"`. | `"3"` |
| `last_seen__exact` | String | ISO 8601 Timestamp of last observation. | `"2023-10-27T10:00:00Z"` |
| `site_id__exact` | Integer | Unique identifier for the physical/logical site. | `1` |
| `special_hint__exact` | Integer | Address type. **Enums:** `0` (unicast), `1` (broadcast), `2` (multicast), `3` (out of scope), `4` (external). | `0` |
| `insight_name__exact` | String | Filter by exact insight name. *(Call `get_common_schema` for Insight Type Enums)* | `"Unsecured Protocols"` |
"""