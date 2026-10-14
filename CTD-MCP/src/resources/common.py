# src/resources/common.py

COMMON_SCHEMA_URI = "resource://ctd/common-schema"
    
COMMON_SCHEMA_DOCS = """# CTD Common Schema & Enums

This document provides shared enums and return fields used across multiple tools (e.g., `search_assets`, `search_insights`, `filter_assets_by_insight_key`).

## 1. Allowed Asset Return Fields
Only request the fields necessary to answer the user's prompt.
* **Identity:** `id`, `name`, `display_name`, `hostname`, `mac`, `serial_number`, `edge_id`
* **Network:** `ipv4`, `ipv6`, `vlan`, `gateway`, `default_gateway`, `network_id`, `subnet_id`, `protocol`
* **Classification:** `vendor`, `model`, `firmware`, `asset_type`, `class_type`, `os`, `os_build`, `os_architecture`, `os_service_pack`
* **Location/Topology:** `site_id`, `site_name`, `virtual_zone_id`, `virtual_zone_name`, `purdue_level`
* **Risk & Posture:** `risk_level`, `risk_score`, `criticality`, `num_alerts`, `insight_names`
* **Software/State:** `installed_antivirus`, `patch_count`, `installed_programs_count`, `plc_slots`, `state`, `domain_workgroup`
* **Status:** `approved`, `valid`, `ghost`, `timestamp`, `first_seen`, `last_seen`
* **Details/Custom Information:** `custom_informations`, `custom_attributes`

---

## 2. Asset Type Enums (`asset_type__exact`)
When filtering by asset type, use the corresponding Integer value from this table:

| ID | Asset Type | ID | Asset Type | ID | Asset Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0` | ePLC | `1` | eHMI | `2` | eEndpoint |
| `3` | eNetworking | `4` | eBroadcast | `5` | eDomainController |
| `6` | ePrinter | `7` | eSCADAClient | `8` | eSCADAServer |
| `9` | eHistorian | `10` | eFileServer | `11` | eRouter |
| `12` | eSwitch | `13` | eRemoteIO | `14` | eEngineeringStation |
| `15` | eGateway | `16` | eOPCServer | `17` | eOT |
| `18` | eRTU | `19` | eIED | `20` | eController |
| `21` | eNTPServer | `22` | eUserConsole | `23` | eUserWorkstation |
| `24` | eTerminalServer | `25` | eSyslogServer | `26` | eFrontEndProcessor |
| `27` | eModem | `28` | eProxyServer | `29` | eReverseProxyServer |
| `30` | eNetworkAccessStorage | `31` | eFirewall | `32` | eAVServer |
| `33` | eADServer | `34` | eWebServer | `35` | eDBServer |
| `36` | eStorageArray | `37` | eGPSClock | `38` | eSCADAMaster |
| `39` | eVoipPhone | `40` | eTVScreen | `41` | eBluetoothDevice |
| `42` | eCamera | `43` | eVendingMachine | `44` | eSmartPhone |
| `45` | eSmartWatch | `46` | eInfusionPump | `47` | eMedicalDevice |
| `48` | eBarcodeScanner | `49` | eMicroscope | `50` | eAccessControl |
| `51` | eSmartLight | `52` | eStreamer | `53` | eHomeAssistant |
| `54` | eMediaServer | `55` | eCleaningDevice | `56` | eVoipServer |
| `57` | eRobot | `58` | eAutonomousVehicle | `59` | eWirelessLanController |
| `60` | eAccessPoint | `61` | eAAAServer | `62` | eGPSDevice |
| `63` | eUPS | `64` | eVideoRecorder | `65` | eVirtualizationServer |
| `66` | eDataLogger | `67` | eSensor | `68` | eElectricalDrive |
| `69` | eMotorStarter | `70` | eVulnerabilityScanner | `71` | eVOIPAccessPoint |
| `72` | eSNMPServer | `73` | eSNMPScanner | `74` | eBiometricScanner |
| `75` | eDNSServer | `76` | eVisionCamera | `77` | eBarcodeReader |
| `78` | eVisionController | `79` | eVisionSensor | `80` | eRTLS |
| `81` | eCNC | `82` | eCNCMill | `83` | eCNCLathe |
| `84` | eAnalysisStation | `85` | eWeightSensor | `86` | eXRayCargoScanner |

---

## 3. Insight Name Enums (`insight_name__exact`)
When filtering by insight name, pass the exact string value from the **Insight Name** column (e.g., `"Unsecured Protocols"`):

| ID | Insight Name | ID | Insight Name |
| :--- | :--- | :--- | :--- |
| `1` | Windows CVEs | `18` | Assets Accessed SMB shares |
| `2` | Full Match CVEs | `19` | SNMP Querying Assets |
| `3` | Model Match CVEs | `20` | Unsecured Protocols |
| `4` | Vendor Match CVEs | `21` | Web Servers |
| `5` | Top Risky Assets | `22` | Data Acquisition Write (Operated PLCs) |
| `6` | DHCP Clients | `23` | Windows CVEs Full Match |
| `8` | Talking with External IPs | `24` | Program Match CVEs |
| `9` | Files Downloaded (clients) | `25` | SMBv1 Negotiate |
| `10` | Talking with Ghost Assets | `27` | PLCs talking IT protocol |
| `11` | Multiple Interfaces | `28` | Remote desktop application |
| `12` | Highly Connected Assets | `29` | USB devices connected to assets |
| `13` | Open Ports | `30` | Assets with partial connection to the internet |
| `14` | Privileged Operations (Operated PLCs) | `31` | Using unencrypted and weak passwords |
| `15` | Clients remotely managed | `32` | PLCs exposed to program changes |
| `16` | Managed PLCs (by Rockwell users) | `33` | PLCs exposed to Triton |
| `17` | Assets accessing SMB Pipes | `34` | End Of Life Assets |
| | | `35` | Unsupported OS |
"""