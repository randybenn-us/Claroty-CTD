# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Author       : Pranjali Sanwal
# Project      : Claroty CTD Best Practice Wizard (MVP)
# Scope        : Federal POV Drift Analysis & Automated Audit
# =============================================================================

# Disable SSL Certificate Warnings for Self-Signed CTD Certificates
if ($PSVersionTable.PSVersion.Major -ge 6) {
    # PowerShell Core / PS 7+ handle certificate bypass via -SkipCertificateCheck on Invoke-RestMethod
} else {
    # Windows PowerShell 5.1 fallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

$SCRIPT_VERSION = "v26"

# =============================================================================
# SYSTEM DEFAULTS & BASELINES
# =============================================================================
$DEFAULT_CONFIG = @{
    "fips_enabled"           = $false
    "training_mode"          = $true
    "max_ram_pct"            = 80.0
    "max_cpu_pct"            = 80.0
    "max_disk_pct"           = 80.0
    "require_span_interface" = $true
}

$DEFAULT_PROTOCOLS = [ordered]@{
    "honeywell.Firewall" = $true; "cclink_ie.cclink_ie_field" = $true; "fortinet_discovery" = $true;
    "toshiba_tcnet" = $true; "terasaki.layer_2_broadcast" = $true; "rapienet" = $false; "rpc" = $true;
    "dns" = $true; "ssh" = $true; "dhcp" = $true; "ftp" = $true; "ftp_data" = $true; "http" = $true;
    "icmp" = $true; "igmp" = $true; "modbus.tcp" = $true; "browser" = $true; "arp" = $true; "cip" = $true;
    "enip" = $true; "s7comm" = $true; "profinet.dcp" = $true; "llc" = $true; "lldp" = $true; "dcerpc" = $true;
    "mms" = $true; "tftp" = $true; "profinet.pn_io" = $true; "ntp" = $true; "opc_ua" = $true; "nbdgm" = $true;
    "ntlmssp" = $true; "samr" = $true; "vnc" = $true; "ssl" = $true; "s7commplus" = $true; "cotp" = $true;
    "smb" = $true; "smb_pipe" = $true; "lanman" = $true; "atsvc" = $true; "srvsvc" = $true; "rdp" = $true;
    "ge_srtp" = $true; "goose" = $true; "egd" = $true; "roc_plus" = $true; "bnc" = $true; "ge_sdi" = $true;
    "ge_sdiclassic" = $true; "ge_quickpanel" = $true; "foxboro" = $true; "ff" = $false; "honeywell.FtebCipMsg" = $false;
    "honeywell.PsCdaCeeNtComm" = $false; "ldap" = $false; "kerberos" = $false; "rlogin" = $false; "smtp" = $false;
    "pop" = $false; "imap" = $false; "honeywell.PsCdaCeeNtPeer" = $false; "hart_ip" = $false; "telnet" = $false;
    "totalflow" = $false; "bacnet" = $false; "ovation" = $false; "fwl_load" = $false; "symphony_plus" = $false;
    "pinet.pi1" = $false; "pinet.pi3" = $true; "iec104" = $false; "rcdp" = $true; "eterra" = $false;
    "eterra_workstation" = $false; "abb_dms" = $false; "red_lion" = $true; "synchrophasor" = $true; "mqtt" = $true;
    "citect" = $true; "keyence.keyence_kv_studio" = $true; "profinet.rt" = $true; "beckhoff" = $true; "tpkt" = $true;
    "portmapper" = $true; "hsrp" = $true; "cpha" = $true; "rtcp" = $true; "ge_enervista" = $false; "epm" = $true;
    "sel" = $true; "sip" = $true; "skinny" = $true; "radius" = $true; "capwap_control" = $true; "capwap_data" = $true;
    "wlan" = $true; "hp_switch" = $true; "ptp" = $true; "abb_melody" = $true; "factorytalk_rna" = $true;
    "valmet_dna.damatic_configuration" = $true; "sampled_values" = $true; "cspv4" = $true; "hirschmann" = $true;
    "digi_real_port" = $true; "ethercat" = $true; "mdns" = $true; "llmnr" = $true; "icmpv6" = $true; "nbns" = $true;
    "h1" = $true; "bittorrent" = $true; "fins.tcp" = $true; "melsec" = $true; "ovation.ovationrpc" = $true;
    "red_lion.red_lion_discovery" = $true; "tridium_fox" = $true; "sattbus" = $true; "vnet.odeq" = $true;
    "vnet" = $true; "vnet.vhf" = $true; "ovation.alarm" = $true; "modbus.serial" = $true; "proconos" = $true;
    "tsaa" = $true; "tristation" = $true; "axe" = $true; "deltav.device_connection" = $true; "deltav.RtProgLog" = $true;
    "deltav.FlashDownload" = $true; "omniflow" = $true; "dnp3" = $true; "egd_cmp" = $true; "p2" = $false;
    "ovation.dbxmit" = $false; "ovation.ptedit" = $false; "honeywell.comm_setup" = $false; "honeywell.EpicMo" = $false;
    "opto" = $false; "opto_mmp" = $false; "lantronix" = $false; "cti" = $false; "bailey.tcp" = $false;
    "bailey.serial" = $false; "ge_alm" = $true; "prosoft_discovery" = $true; "iec101" = $false;
    "bailey.infininet" = $false; "secsgem" = $false; "dacp" = $false; "iec103" = $false; "keyence.keyence_log_reporter" = $true;
    "cognex_discovery" = $true; "kongsberg" = $true; "portwell" = $true; "ovation.admd" = $false; "mndp" = $true;
    "siprotec" = $true; "keyence.keyencehostlink" = $false; "foxboro_rtv" = $true; "knapp" = $true; "linux_ha" = $true;
    "comtrol_ns_link" = $true; "slmp" = $true; "melsoft" = $true; "wonderware.iotalk" = $true; "altus.alnet" = $true;
    "alspa" = $true; "schneider_netmanage" = $true; "bnr.ina2000" = $true; "mdlc.mdlc_management" = $true;
    "mdlc.mdlc_data" = $true; "caterpillar.gw_to_vims" = $false; "caterpillar.hmi_to_gw" = $false; "wsd" = $true;
    "abb_dcs.rnrp" = $true; "cygnet" = $false; "enhanced_modbus" = $true; "java.jrmi" = $true; "java.java_rpc" = $true;
    "t3000.automation_server_data" = $true; "t3000.gw_discover" = $true; "nmea_0183" = $true; "opto_softpac_agent" = $false;
    "honeywell.safety_manager" = $true; "honeywell.dsa_discovery" = $true; "iq3" = $true; "valmet_dna.valmet_dna_data" = $true;
    "valmet_dna.valmet_dna_frontend" = $false; "valmet_dna.valmet_dna_alarms" = $true; "wudo" = $true; "sentinel_srm" = $true;
    "valmet_dna.damatic_data" = $true; "bsap" = $true; "clear_scada" = $true; "matrikon_opc" = $true; "sbus" = $true;
    "moxa_udp" = $true; "schneider_ion" = $true; "ethernet_powerlink" = $true; "trdp.trdp_pd" = $true; "koyo" = $true;
    "xpact.xpact_data" = $true; "xpact.xpact_discovery" = $true; "xpact.xpact_diagnostics" = $true; "cola_a" = $true;
    "zabbix.zabbix_agent" = $true; "zabbix.zabbix_sender" = $true; "sinaut_fw8" = $false; "ttsac" = $true;
    "ge_ifix" = $true; "wago" = $true; "siemens_iem" = $true; "max_dna" = $false; "codesysv3" = $true; "xg5000" = $true;
    "flnet" = $true; "pf_dcp" = $true; "gaz_modem" = $true; "codesysv2" = $true; "dlms_cosem" = $true; "b32" = $false;
    "snmp" = $true; "pcwin" = $false; "tds" = $true; "mitsubishi_got" = $true; "jrc_vessel_display" = $true; "focas" = $true;
    "gcode" = $false; "exi3000.discovery" = $false; "exi3000.mgmt" = $false; "meggitt.vibrometer" = $true;
    "abb_netconfig" = $true; "fins.udp" = $true; "terasaki.negotiation" = $true; "terasaki.realtime_data_sync" = $false;
    "siemens_cargo.cargo_compact" = $true; "siemens_cargo.cargo_compact_sensor" = $false;
    "siemens_cargo.cargo_compact_control" = $false; "smiths_detection.broadcast" = $true; "mdlc.mdlc_proprietary" = $false;
    "telvent.oasys" = $false
}

# Date and Time
$current_date = (Get-Date).ToString("MM/dd/yyyy")
$current_time = (Get-Date).ToString("HH:mm:ss zzz")
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

Write-Host ("=" * 70)
Write-Host "   Claroty CTD Best Practice Wizard - Master Collector $SCRIPT_VERSION"
Write-Host ("=" * 70)

# CTD Server Info (Interactive Input)
$ctd_ip = (Read-Host "Enter CTD IP or hostname").Trim()
$username = (Read-Host "Enter CTD username").Trim()

# Masked Password Prompt in PowerShell using Read-Host -AsSecureString
$securePassword = Read-Host "Enter CTD password" -AsSecureString
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
)

Write-Host "`n--- Output Formats ---"
Write-Host "Available formats: txt, html, json, md, csv"
$output_prefs = (Read-Host "Enter desired output formats (comma-separated) or 'all'").Trim().ToLower()

$valid_formats = @('txt', 'html', 'json', 'md', 'csv')
if ($output_prefs -contains 'all') {
    $selected_outputs =$valid_formats
} else {
    $selected_outputs = $output_prefs.Split(',') | ForEach-Object {$_.Trim() } | Where-Object { $valid_formats -contains$_ }
    if ($selected_outputs.Count -eq 0) {
        Write-Host "[!] No valid format selected. Defaulting to 'txt'."
        $selected_outputs = @('txt')
    }
}

# Helper Rest Function
function Invoke-CTDRest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body =$null,
        [int]$TimeoutSec = 15
    )

    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        TimeoutSec      = $TimeoutSec
        ErrorAction     = 'Stop'
    }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $params['SkipCertificateCheck'] =$true
    }

    if ($Body) {$params['ContentType'] = 'application/json'
        if ($Body -is [string]) {
            $params['Body'] =$Body
        } else {
            $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
        }
    }

    return Invoke-RestMethod @params
}

# Helper Private IP RFC1918 Check
function Test-IsPrivateIP {
    param([string]$ipString)
    try {
        $cleanIp =$ipString.Split('/')[0]
        $ip = [System.Net.IPAddress]::Parse($cleanIp)
        $bytes =$ip.GetAddressBytes()
        if ($bytes[0] -eq 10) { return$true }
        if ($bytes[0] -eq 172 -and ($bytes[1] -ge 16 -and $bytes[1] -le 31)) { return$true }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return$true }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return$true }
        return $false
    } catch {
        return $true
    }
}

# Authentication Setup
$authBody = @{ username =$username; password = $password }
$headers = @{ 'Content-type' = 'application/json'; 'Accept' = 'application/json' }

Write-Host "`n[*] Authenticating with Claroty CTD at $ctd_ip..."
try {
    $doauth = Invoke-CTDRest -Uri "https://$ctd_ip/auth/authenticate" -Method "POST" -Headers $headers -Body $authBody
} catch {
    Write-Host "Connection Error during authentication: $_"
    exit 1
}

if (-not $doauth -or -not $doauth.token) {
    Write-Host "Authentication Failed. No token received."
    exit 1
}

Write-Host "Successful Login"

$ctd_auth_token = $doauth.token
$getauthheaders = @{ 'Authorization' = $ctd_auth_token; 'Accept' = 'application/json' }

# Dictionaries and lists to track report output
$report_metrics = [ordered]@{}
$actionable_insights = [System.Collections.Generic.List[string]]::new()

# Global variables for Header System Summary
$extracted_base_version = "Unknown"
$extracted_update_version = "Unknown"
$extracted_threat_bundle = "Unknown"
$extracted_system_mode = "Unknown"
$extracted_fips_mode = "Unknown"
$extracted_zone_grouping = "Unknown"
$extracted_alert_sensitivity = "Unknown"
$extracted_assets_summary = "Total: N/A | IT: N/A | OT: N/A | IoT: N/A"

# =============================================================================
# 1. AUDIT: Remote CTD Server System Health Dashboard
# =============================================================================
Write-Host "[*] Fetching Metric: Remote System Health Dashboard..."
try {
    $health_res = $null
    try {
        $health_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/system_health" -Headers $getauthheaders
    } catch {
        $health_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/ranger_api/system_health" -Headers $getauthheaders
    }

    $cpu_pct = "N/A"
    $ram_pct = "N/A"
    $partitions_summary = [ordered]@{}
    $assessment_status = "REVIEW"

    if ($health_res) {
        $data_block = $health_res.data
        $site_data = $null

        if ($data_block -is [PSCustomObject]) {
            foreach ($prop in $data_block.psobject.Properties) {
                if ($prop.Value.factors) {
                    $site_data = $prop.Value
                    break
                }
            }
        }

        $factors = $site_data.factors
        $system_factor = $null

        if ($factors -is [PSCustomObject]) {
            if ($factors.application_health -and $factors.application_health.system_status) {
                $system_factor = $factors.application_health.system_status
            } else {
                $system_factor = $factors.system_status
            }
        } elseif ($factors -is [System.Array]) {
            $system_factor = $factors | Where-Object { $_.type -eq "system_status" } | Select-Object -First 1
        }

        if ($system_factor) {
            $info_block = $system_factor.info
            $sys_status = if ($info_block) { $info_block.system_status } else { $null }

            if ($sys_status) {
                $raw_cpu = if ($sys_status.cpu.value) { $sys_status.cpu.value } else { $sys_status.cpu }
                $raw_ram = if ($sys_status.memory.value) { $sys_status.memory.value } else { $sys_status.memory }

                if ($null -ne $raw_cpu) { $cpu_pct = "$raw_cpu%" }
                if ($null -ne $raw_ram) { $ram_pct = "$raw_ram%" }

                try {
                    $ram_float = [double]("$raw_ram".Replace('%', ''))
                    $cpu_float = [double]("$raw_cpu".Replace('%', ''))
                    $max_ram = $DEFAULT_CONFIG["max_ram_pct"]
                    $max_cpu = $DEFAULT_CONFIG["max_cpu_pct"]

                    if ($ram_float -gt $max_ram) {
                        $actionable_insights.Add("Server Health: Server Memory ($ram_pct) exceeds the baseline threshold of $max_ram%.")
                    }
                    if ($cpu_float -gt $max_cpu) {
                        $actionable_insights.Add("Server Health: Server CPU ($cpu_pct) exceeds the baseline threshold of $max_cpu%.")
                    }
                } catch {}

                $disk_block = $sys_status.disk
                $display_names = @{ "os" = "OS (/)"; "data" = "Data (/var)"; "logs" = "Logs (/var/log)"; "temp" = "Temp (/tmp)"; "audit" = "Audit (/var/log/audit)" }
                $max_disk = $DEFAULT_CONFIG["max_disk_pct"]
                $disk_violation = $false

                if ($disk_block) {
                    foreach ($prop in $disk_block.psobject.Properties) {
                        $key = $prop.Name
                        $part = $prop.Value
                        $name = if ($display_names.ContainsKey($key)) { $display_names[$key] } else { "Partition ($key)" }
                        
                        $pct = $null
                        if ($null -ne $part.percentage) {
                            $pct = $part.percentage
                        } elseif ($part.total -and $part.total -gt 0) {
                            $pct = [math]::Round(($part.used / $part.total) * 100, 2)
                        }

                        if ($null -ne $pct) {
                            $partitions_summary[$name] = if ($pct -gt 0 -and $pct -lt 0.1) { "<0.1%" } else { "$pct%" }
                            if ($pct -gt $max_disk) {
                                $actionable_insights.Add("Server Health: Storage $name ($pct%) exceeds the baseline threshold of $max_disk%.")
                                $disk_violation = $true
                            }
                        }
                    }
                }

                $assessment_status = if ($ram_float -le $DEFAULT_CONFIG["max_ram_pct"] -and $cpu_float -le $DEFAULT_CONFIG["max_cpu_pct"] -and -not $disk_violation) { "PASS" } else { "REVIEW" }
            }
        }
    }

    if ($partitions_summary.Count -eq 0) { $partitions_summary["Error"] = "No storage partitions parsed." }

    $health_table = [System.Collections.Generic.List[string]]::new()
    $health_table.Add("=" * 50)
    $health_table.Add(("{0,-25} | {1}" -f "METRIC", "VALUE"))
    $health_table.Add("-" * 50)
    $health_table.Add(("{0,-25} | {1}" -f "Server CPU", $cpu_pct))
    $health_table.Add(("{0,-25} | {1}" -f "Server Memory", $ram_pct))
    $health_table.Add("-" * 50)
    $health_table.Add("STORAGE PARTITIONS")
    foreach ($k in $partitions_summary.Keys) {
        $health_table.Add(("{0,-25} | {1}" -f $k, $partitions_summary[$k]))
    }
    $health_table.Add("=" * 50)

    $report_metrics["System Health Summary"] = @{ "status" = $assessment_status; "raw" = ($health_table -join "`n") }
} catch {
    $report_metrics["System Health Summary"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# 2. AUDIT: License Status
# =============================================================================
Write-Host "[*] Fetching Metric: System License Status..."
try {
    $lic_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/license?site_id=1" -Headers $getauthheaders
    if ($lic_data -and$lic_data.success -eq $true) {$status_color = "$($lic_data.data.status)".ToLower()
        $is_fips = [bool]$lic_data.data.is_fips
        $exp_date_str = "$($lic_data.data.expiration_date)"
        
        $assessment_status = if ($status_color -eq "green") { "PASS" } else { "FAIL" }
        $extracted_fips_mode = if ($is_fips) { "Yes" } else { "No" }
        $days_left_str = "N/A"

        if ($exp_date_str) {
            $exp_date = [datetime]::Parse($exp_date_str.Substring(0, 10))
            $days_left = ($exp_date - (Get-Date).Date).Days
            $days_left_str = "$days_left remaining"
            if ($days_left -le 14) {$assessment_status = "REVIEW"
                $actionable_insights.Add("License: License expires in $days_left days. Recommend requesting a new license.")
            }
        }

        $lic_table = [System.Collections.Generic.List[string]]::new()
        $lic_table.Add("=" * 60)
        $lic_table.Add(("{0,-25} | {1}" -f "LICENSE ATTRIBUTE", "VALUE"))
        $lic_table.Add("-" * 60)
        $lic_table.Add(("{0,-25} | {1}" -f "Status", (Get-Culture).TextInfo.ToTitleCase($status_color)))
        $lic_table.Add(("{0,-25} | {1}" -f "FIPS Mode", $is_fips))
        $lic_table.Add(("{0,-25} | {1}" -f "Expiration Date", $exp_date_str))
        $lic_table.Add(("{0,-25} | {1}" -f "Days Remaining", $days_left_str))
        $lic_table.Add("=" * 60)

        $report_metrics["License Status"] = @{ "status" = $assessment_status; "raw" = ($lic_table -join "`n") }
    } else {
        $report_metrics["License Status"] = @{ "status" = "ERROR"; "raw" = "Failed to parse license data." }
    }
} catch {
    $report_metrics["License Status"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# 3. AUDIT: Virtual Zones List
# =============================================================================
Write-Host "[*] Fetching Metric: Virtual Zone Allocations..."
try {
    $zone_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/virtual_zones" -Headers $getauthheaders
    if ($zone_data -and $zone_data.objects) {
        $zone_count = $zone_data.objects.Count
        $assessment_status = if ($zone_count -gt 0) { "PASS" } else { "REVIEW" }

        $zt_lines = [System.Collections.Generic.List[string]]::new()
        $zt_lines.Add("=" * 80)
        $zt_lines.Add(("{0,-5} | {1,-35} | {2,-15} | {3}" -f "ID", "ZONE NAME", "CRITICALITY", "ASSETS"))
        $zt_lines.Add("-" * 80)
        foreach ($z in $zone_data.objects) {
            $z_crit = "$($z.criticality__)".Replace('e', '')
            if (-not $z_crit) { $z_crit = "Unknown" }
            $zt_lines.Add(("{0,-5} | {1,-35} | {2,-15} | {3}" -f $z.id, $z.name, $z_crit, $z.num_assets))
        }
        $zt_lines.Add("=" * 80)

        $report_metrics["Virtual Zones List"] = @{ "status" = $assessment_status; "raw" = ($zt_lines -join "`n") }
    } else {
        $report_metrics["Virtual Zones List"] = @{ "status" = "ERROR"; "raw" = "No zone data found." }
    }
} catch {
    $report_metrics["Virtual Zones List"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# 4. AUDIT: Subnet Table Summary
# =============================================================================
Write-Host "[*] Fetching Metric: Formatted Subnet Table..."
try {
    $subnet_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/subnets?sort=name&page=1&per_page=50&with_assets__exact=true&site_id__exact=1&distinct=false" -Headers $getauthheaders
    $TYPE_MAPPING = @{ 0 = "Internal"; 1 = "External" }

    if ($subnet_data -and$subnet_data.objects) {
        $table_lines = [System.Collections.Generic.List[string]]::new()
        $table_lines.Add("=" * 80)
        $table_lines.Add(("{0,-3} | {1,-18} | {2,-15} | {3,-12} | {4}" -f "#", "SUBNET IP", "NETWORK", "TYPE", "ASSETS"))
        $table_lines.Add("-" * 80)

        $count = 1
        foreach ($item in $subnet_data.objects) {$subnet_ip = if ($item.name) {$item.name } elseif ($item.subnet) {$item.subnet } else { "Unknown" }
            $network = if ($item.network_name) {$item.network_name } elseif ($item.network) {$item.network } else { "N/A" }
            $assets = if ($item.num_assets) {$item.num_assets } elseif ($item.assets_count) {$item.assets_count } else { 0 }
            
            $raw_type =$item.type
            $subnet_type = if ($null -ne $raw_type -and $TYPE_MAPPING.ContainsKey([int]$raw_type)) {$TYPE_MAPPING[[int]$raw_type] } else { "Type $raw_type" }

            if ($subnet_ip -and $subnet_ip -ne "Unknown") {
                if (-not (Test-IsPrivateIP -ipString $subnet_ip)) {$actionable_insights.Add("Subnets: RFC-1918 addresses only; ensure no public IPs used internally (Flagged: $subnet_ip)")
                }
            }

            $table_lines.Add(("{0,-3} | {1,-18} | {2,-15} | {3,-12} | {4}" -f $count, $subnet_ip, $network, $subnet_type, $assets))
            $count++
        }
        $table_lines.Add("=" * 80)
        $report_metrics["Subnet Table Summary"] = @{ "status" = "PASS"; "raw" = ($table_lines -join "`n") }
    } else {
        $report_metrics["Subnet Table Summary"] = @{ "status" = "REVIEW"; "raw" = "No subnet data objects found." }
    }
} catch {
    $report_metrics["Subnet Table Summary"] = @{ "status" = "ERROR"; "raw" = "Error formatting subnet table: $_" }
}

# =============================================================================
# 5. AUDIT: System Versions, Updates & Threat Bundles
# =============================================================================
Write-Host "[*] Fetching Metric: System Versions & Threat Bundles..."
try {
    $base_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/current_version?ids=1" -Headers $getauthheaders
    $update_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/current_update_version?site_id=1" -Headers $getauthheaders
    $bundle_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/ranger_api/last_date_of_update?site_id__exact=1" -Headers $getauthheaders

    if ($base_res -and $base_res.data) {
        foreach ($prop in $base_res.data.psobject.Properties) {
            if ($prop.Value.response) {
                $extracted_base_version = "$($prop.Value.response)"
                break
            }
        }
    }

    if ($update_res -and $update_res.data) {
        $extracted_update_version = "$($update_res.data.update_version)"
    }

    if ($extracted_update_version -in @("Unknown", "None", "", "0")) {
        $actionable_insights.Add("Version: No version update reported means none applied; suggested applying latest available update.")
    }

    if ($bundle_res -and $bundle_res.data) {
        $extracted_threat_bundle = "$($bundle_res.data.bundle_id)"
        $last_issue_str = "$($bundle_res.data.last_date_of_issue)"
        if ($last_issue_str) {
            try {
                $issue_date = [datetime]::Parse($last_issue_str.Substring(0, 10))
                $days_old = ((Get-Date).Date - $issue_date).Days
                if ($days_old -gt 30) {
                    $actionable_insights.Add("Threat Bundle: Threat Bundle update > 30 days ($days_old days old). Check for a newer version.")
                }
            } catch {}
        }
    }
} catch {}

# =============================================================================
# 6. AUDIT: System Mode
# =============================================================================
Write-Host "[*] Fetching Metric: CTD Operational Mode..."
try {
    $mode_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/sites?format=site_list_slim&sort=name&page=1&per_page=0" -Headers $getauthheaders
    if ($mode_res -and $mode_res.objects -and $mode_res.objects.Count -gt 0) {
        $live_training_mode = [bool]$mode_res.objects[0].training_mode
        $extracted_system_mode = if ($live_training_mode) { "Training" } else { "Operational" }

        if ($live_training_mode) {
            $actionable_insights.Add("System Mode: Training mode - Behavioral threat detection not possible.")
        }
    }
} catch {}

# =============================================================================
# 7. AUDIT: Virtual Zone Grouping Algorithm
# =============================================================================
Write-Host "[*] Fetching Metric: Virtual Zone Grouping Algorithm..."
try {
    $vz_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/virtual_zones_grouping_algorithm?site_id=1" -Headers $getauthheaders
    if ($vz_res) {
        $GUI_MAPPINGS = @{
            "default" = "Default Behavioral Grouping Algorithm"
            "purdue"  = "Purdue Model Grouping"
            "network" = "Network Subnet Grouping"
            "custom"  = "Custom Grouping Algorithm"
        }

        $raw_json = $vz_res | ConvertTo-Json -Depth 5
        foreach ($key in $GUI_MAPPINGS.Keys) {
            if ($raw_json -like "*$key*") {
                $extracted_zone_grouping = $GUI_MAPPINGS[$key]
                break
            }
        }
    }
} catch {}

# =============================================================================
# 8. AUDIT: Alert Sensitivity 
# =============================================================================
Write-Host "[*] Fetching Metric: Alert Sensitivity..."
try {
    $alert_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/alerts/score_config?site_id=1" -Headers $getauthheaders
    if ($alert_res) {
        if ($alert_res.alerts_threshold) {
            $extracted_alert_sensitivity = "$($alert_res.alerts_threshold)"
        } else {
            $raw_json = $alert_res | ConvertTo-Json -Depth 5
            if ($raw_json -match '"alerts_threshold"\s*:\s*"([^"]+)"') {
                $extracted_alert_sensitivity = $Matches[1]
            }
        }
    }
} catch {}

# =============================================================================
# 9. AUDIT: Asset Counts & Categorization Breakdown
# =============================================================================
Write-Host "[*] Fetching Metric: Asset Summary Breakdown..."
try {
    $total_a = 0; $it_a = 0; $ot_a = 0; $iot_a = 0
    $one_year_ago = ([datetime]::UtcNow.AddDays(-365)).ToString("yyyy-MM-ddTHH:mm:ss.000Z")

    $base_url = "https://$ctd_ip/ranger/assets?format=asset_list&ghost__exact=false&special_hint__exact=0&insight_status__exact=0&site_id__exact=1&last_seen__gte=$one_year_ago&count_only=true"

    $tot_res = Invoke-CTDRest -Uri $base_url -Headers $getauthheaders
    if ($tot_res) { $total_a = if ($tot_res.count_total) { $tot_res.count_total } else { $tot_res.total } }

    $it_res = Invoke-CTDRest -Uri "$base_url&class_type__exact=1" -Headers $getauthheaders
    if ($it_res) { $it_a = if ($it_res.count_total) { $it_res.count_total } else { $it_res.total } }

    $ot_res = Invoke-CTDRest -Uri "$base_url&class_type__exact=0" -Headers $getauthheaders
    if ($ot_res) { $ot_a = if ($ot_res.count_total) { $ot_res.count_total } else { $ot_res.total } }

    $iot_res = Invoke-CTDRest -Uri "$base_url&class_type__exact=2" -Headers $getauthheaders
    if ($iot_res) { $iot_a = if ($iot_res.count_total) { $iot_res.count_total } else { $iot_res.total } }

    $extracted_assets_summary = "Total: $total_a | IT: $it_a | OT: $ot_a | IoT: $iot_a"
} catch {}

# =============================================================================
# 10. AUDIT: Collection Methods & Sensors
# =============================================================================
Write-Host "[*] Fetching Metric: Connected Collection Sensors Health..."
try {
    $sensor_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/system/check?site_id=1" -Headers $getauthheaders
    $assessment_status = if ($sensor_data -and $sensor_data.success) { "INFO" } else { "FAIL" }

    $sensor_table = [System.Collections.Generic.List[string]]::new()
    $sensor_table.Add("=" * 80)
    $sensor_table.Add(("{0,-40} | {1,-15} | {2}" -f "SENSOR NAME", "IP ADDRESS", "CONNECTED"))
    $sensor_table.Add("-" * 80)

    $parents = $sensor_data.data.statuses.parents
    if ($parents) {
        foreach ($p in $parents) {
            $sensor_table.Add(("{0,-40} | {1,-15} | {2}" -f $p.name, $p.address, $p.is_connected))
        }
    } else {
        $sensor_table.Add(("{0,-40} | {1,-15} | {2}" -f "No sensors connected", "N/A", "N/A"))
    }
    $sensor_table.Add("=" * 80)

    $report_metrics["Collection Methods / Sensors"] = @{ "status" = $assessment_status; "raw" = ($sensor_table -join "`n") }
} catch {
    $report_metrics["Collection Methods / Sensors"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# 11. AUDIT: Interface List
# =============================================================================
Write-Host "[*] Fetching Metric: Network Interfaces..."
try {
    $remote_name =$null
    try {
        $loc_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/wizard/remote_locations?site_id=1" -Headers $getauthheaders
        if ($loc_res -is [System.Array] -and$loc_res.Count -gt 0) {
            $remote_name =$loc_res[0].id
        } elseif ($loc_res.objects -and$loc_res.objects.Count -gt 0) {
            $remote_name =$loc_res.objects[0].id
        }
    } catch {}

    if (-not $remote_name) {
        try {
            $lic_res = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/license?site_id=1" -Headers $getauthheaders
            $remote_name =$lic_res.data.machine_uuid
        } catch {}
    }

    if (-not $remote_name) {$remote_name = "072043d5-2ad1-5937-e26a-c5d0ec0b09ff" }

    $iface_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/wizard/interfaces?remote_name=$remote_name&site_id=1" -Headers $getauthheaders
    $iface_list =$iface_data.data

    if ($DEFAULT_CONFIG["require_span_interface"]) {
        $has_ingestion =$false
        foreach ($iface in $iface_list) {
            if ($iface.is_management -eq$false -and $iface.enabled -eq$true) {
                $has_ingestion =$true
                break
            }
        }
        if (-not $has_ingestion) {$actionable_insights.Add("Interfaces: No DPI interfaces detected; Continuous monitoring and threat detection is not possible.")
        }
    }

    $iface_table = [System.Collections.Generic.List[string]]::new()
    $iface_table.Add("=" * 95)
    $iface_table.Add(("{0,-25} | {1,-15} | {2,-20} | {3,-12} | {4}" -f "INTERFACE", "IP ADDRESS", "MAC ADDRESS", "PROCESS DATA", "MANAGEMENT"))
    $iface_table.Add("-" * 95)

    if ($iface_list) {
        foreach ($iface in $iface_list) {
            $raw_name = if ($iface.name) { $iface.name } else { 'N/A' }
            $is_mgmt_bool = [bool]$iface.is_management
            $if_name = if ($is_mgmt_bool) { "Management ($raw_name)" } else { $raw_name }
            $proc_data = if ($iface.enabled) { "Enabled" } else { "Disabled" }
            $is_mgmt = if ($is_mgmt_bool) { "True" } else { "False" }

            $iface_table.Add(("{0,-25} | {1,-15} | {2,-20} | {3,-12} | {4}" -f $if_name, $iface.ip, $iface.mac, $proc_data, $is_mgmt))
        }
    } else {
        $iface_table.Add("No network interfaces found.")
    }
    $iface_table.Add("=" * 95)

    $report_metrics["Interface List"] = @{ "status" = "INFO"; "raw" = ($iface_table -join "`n") }
} catch {
    $report_metrics["Interface List"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# 12. AUDIT: Network List (With Known Threat Detection)
# =============================================================================
Write-Host "[*] Fetching Metric: Advanced Network Settings Table..."
try {
    $net_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/networks?sort=name&page=1&per_page=100" -Headers $getauthheaders
    if ($net_data -and $net_data.objects) {
        $net_lines = [System.Collections.Generic.List[string]]::new()
        $net_lines.Add("=" * 105)
        $net_lines.Add(("{0,-3} | {1,-30} | {2,-5} | {3,-22} | {4}" -f "#", "NETWORK / ENVIRONMENT NAME", "ID", "KNOWN THREAT DETECTION", "STORE RAW DATA (PCAP)"))
        $net_lines.Add("-" * 105)

        $count = 1
        foreach ($item in $net_data.objects) {
            $network_name = if ($item.name) { $item.name } else { "Unknown Network" }
            $network_id = if ($item.id) { $item.id } else { "N/A" }
            $known_threats_bool = if ($null -ne $item.use_known_threats) { [bool]$item.use_known_threats } else { $true }
            $save_caps_bool = [bool]$item.save_caps

            $known_threats = if ($known_threats_bool) { "Enabled" } else { "Disabled" }
            $save_caps = if ($save_caps_bool) { "Enabled" } else { "Disabled" }

            if (-not $known_threats_bool) {
                $actionable_insights.Add("Networks: KNOWN THREAT DETECTION is disabled on network profile '$network_name'.")
            }

            $net_lines.Add(("{0,-3} | {1,-30} | {2,-5} | {3,-22} | {4}" -f $count, $network_name, $network_id, $known_threats, $save_caps))
            $count++
        }
        $net_lines.Add("=" * 105)
        $report_metrics["Network List"] = @{ "status" = "PASS"; "raw" = ($net_lines -join "`n") }
    } else {
        $report_metrics["Network List"] = @{ "status" = "REVIEW"; "raw" = "No configured network profiles discovered." }
    }
} catch {
    $report_metrics["Network List"] = @{ "status" = "ERROR"; "raw" = "Error formatting network table: $_" }
}

# =============================================================================
# 13. AUDIT: Deep Packet Inspection (DPI) Protocols Tables & Drift Engine
# =============================================================================
Write-Host "[*] Fetching Metric: DPI Protocols Configurations..."
try {
    $proto_data = Invoke-CTDRest -Uri "https://$ctd_ip/ranger/ranger_api/protocols?site_id=1" -Headers $getauthheaders$assessment_status = "PASS"

    if ($proto_data -and$proto_data.success) {
        $drifted_protocols = [System.Collections.Generic.List[string]]::new()
        $proto_master_list = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($proto in $proto_data.data) {$name = if ($proto.name) {$proto.name } else { "Unknown" }
            $is_en = [bool]$proto.is_enabled

            $proto_master_list.Add([PSCustomObject]@{ Name = $name; Enabled =$is_en })

            if ($DEFAULT_PROTOCOLS.Contains($name)) {
                if ($is_en -ne $DEFAULT_PROTOCOLS[$name]) {
                    $drifted_protocols.Add("'$name' (Live: $is_en, Default:$($DEFAULT_PROTOCOLS[$name]))")
                }
            }
        }

        $sorted_master = $proto_master_list | Sort-Object Name

        $combined_table = [System.Collections.Generic.List[string]]::new()
        $combined_table.Add("Legend: + = Enabled/Turned On | x = Disabled/Turned Off")
        $combined_table.Add("=" * 55)
        $combined_table.Add(("{0,55}" -f "DPI PROTOCOLS"))
        $combined_table.Add("-" * 55)

        foreach ($item in $sorted_master) {
            if ($item.Enabled) {$combined_table.Add(" + $($item.Name)")
            } else {
                $combined_table.Add(" x $($item.Name)")
            }
        }
        $combined_table.Add("=" * 55)

        if ($drifted_protocols.Count -gt 0) {
            $assessment_status = "REVIEW"
            $actionable_insights.Add("Protocols: The following protocols deviate from the default configuration: $($drifted_protocols -join ', ').")
        }

        $report_metrics["DPI Protocols State"] = @{ "status" = $assessment_status; "raw" = ($combined_table -join "`n") }
    }
} catch {
    $report_metrics["DPI Protocols State"] = @{ "status" = "ERROR"; "raw" = "Error: $_" }
}

# =============================================================================
# POST-INSTALL CHECKLIST POPULATION
# =============================================================================
$checklist = @(
    @{ Task = "Verify 'Known Threat Alert Detection' enabled"; Status = if (-not ($actionable_insights | Where-Object { $_ -like "*KNOWN THREAT DETECTION is disabled*" })) { "PASS" } else { "REVIEW" } },
    @{ Task = "Passive Collection: Verify 'Process Data' Enabled on collection interface(s)"; Status = if (-not ($actionable_insights | Where-Object { $_ -like "*No DPI interfaces detected*" })) { "PASS" } else { "REVIEW" } },
    @{ Task = "Passive Collection: Verify traffic counters on collection interface(s)"; Status = "MANUAL" },
    @{ Task = "Verify Server Health Status (CPU, memory, storage, application health) within limits"; Status = $report_metrics["System Health Summary"]["status"] },
    @{ Task = "Verify proper system mode for desired test cases (Training vs. Operational)"; Status = "INFO ($extracted_system_mode)" },
    @{ Task = "Edge: Demo/production license required to support Edge client uploads"; Status = $report_metrics["License Status"]["status"] },
    @{ Task = "Review required protocols on Interface Management"; Status = $report_metrics["DPI Protocols State"]["status"] }
)

# =============================================================================
# OUTPUT GENERATORS
# =============================================================================
Write-Host "`n[*] Generating Selected Reports..."

# --- TXT OUTPUT ---
if ($selected_outputs -contains 'txt') {
    $txt_filename = "ctd_best_practice_report_$timestamp.txt"
    $sb = [System.Text.StringBuilder]::new()

    $null =$sb.AppendLine("=" * 70)
    $null =$sb.AppendLine("                CLAROTY CTD BEST PRACTICE WIZARD REPORT")
    $null =$sb.AppendLine("=" * 70)
    $null = $sb.AppendLine("Script Version   : $SCRIPT_VERSION")
    $null =$sb.AppendLine("Audit Run Date   : $current_date")
    $null =$sb.AppendLine("Audit Run Time   : $current_time`n")

    $null = $sb.AppendLine("--- 1) SUMMARY ---")
    $null = $sb.AppendLine("Target Appliance : $ctd_ip")
    $null = $sb.AppendLine("Base Version     : $extracted_base_version")
    $null = $sb.AppendLine("Update Version   : $extracted_update_version")
    $null = $sb.AppendLine("Threat Bundle    : $extracted_threat_bundle")
    $null = $sb.AppendLine("System Mode      : $extracted_system_mode")
    $null = $sb.AppendLine("FIPS Mode        : $extracted_fips_mode")
    $null = $sb.AppendLine("Zone Grouping    : $extracted_zone_grouping")
    $null = $sb.AppendLine("Alert Sensitivity: $extracted_alert_sensitivity")
    $null = $sb.AppendLine("Assets           : $extracted_assets_summary`n")

    $null =$sb.AppendLine("CHECKLIST VERIFICATION (Post-Install Tasks):")
    foreach ($chk in $checklist) {
        $null =$sb.AppendLine(("  [{0,6}] {1}" -f $chk.Status, $chk.Task))
    }
    $null =$sb.AppendLine("`n" + ("=" * 70) + "`n")

    $null =$sb.AppendLine("--- 2) RECOMMENDATIONS ---")
    if ($actionable_insights.Count -gt 0) {
        $null =$sb.AppendLine("The following deviations from the Golden Baseline require immediate review:`n")
        foreach ($insight in $actionable_insights) {
            $null = $sb.AppendLine("  * $insight")
        }
    } else {
        $null = $sb.AppendLine("System perfectly matches the Federal Golden Baseline configuration. No deviations detected.")
    }
    $null = $sb.AppendLine("`n" + ("=" * 70) + "`n")

    $null = $sb.AppendLine("--- 3) DATA ---`n")
    foreach ($metric in $report_metrics.Keys) {
        $details =$report_metrics[$metric]
        $null = $sb.AppendLine("### $metric ###")
        $null =$sb.AppendLine("STATUS : $($details['status'])`n")
        $null = $sb.AppendLine($details['raw'])
        $null = $sb.AppendLine("`n`n" + ("-" * 70) + "`n")
    }

    Set-Content -Path $txt_filename -Value $sb.ToString() -Encoding UTF8
    Write-Host "[OK] Generated TXT: $txt_filename"
}

# --- JSON OUTPUT ---
if ($selected_outputs -contains 'json') {
    $json_filename = "ctd_best_practice_report_$timestamp.json"
    $json_data = [ordered]@{
        "metadata" = @{
            "target_appliance" = $ctd_ip
            "script_version"   = $SCRIPT_VERSION
            "date"             = $current_date
            "time"             = $current_time
        }
        "summary" = @{
            "base_version"      = $extracted_base_version
            "update_version"    = $extracted_update_version
            "threat_bundle"     = $extracted_threat_bundle
            "system_mode"       = $extracted_system_mode
            "fips_mode"         = $extracted_fips_mode
            "zone_grouping"     = $extracted_zone_grouping
            "alert_sensitivity" = $extracted_alert_sensitivity
            "assets_summary"    = $extracted_assets_summary
        }
        "checklist"       = $checklist
        "recommendations" = $actionable_insights
        "data"            = $report_metrics
    }

    $json_data | ConvertTo-Json -Depth 10 | Set-Content -Path $json_filename -Encoding UTF8
    Write-Host "[OK] Generated JSON: $json_filename"
}

# --- HTML OUTPUT ---
if ($selected_outputs -contains 'html') {
    $html_filename = "ctd_best_practice_report_$timestamp.html"
    $html_sb = [System.Text.StringBuilder]::new()

    $null = $html_sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Claroty CTD Best Practice Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2, h3 { color: #2c3e50; }
        .report-header { border-bottom: 2px solid #34495e; padding-bottom: 20px; margin-bottom: 20px; text-align: center; }
        .meta-info { display: flex; justify-content: space-between; margin-bottom: 20px; font-size: 14px; color: #7f8c8d; }
        .header-summary { background: #ecf0f1; padding: 20px; border-radius: 6px; margin-bottom: 30px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .header-summary p { margin: 5px 0; font-size: 15px; }
        .recommendations { background-color: #fff3cd; border-left: 6px solid #ffeeba; padding: 20px; margin-bottom: 30px; border-radius: 4px; }
        .recommendations li { padding: 8px 0; color: #856404; font-weight: 500; list-style: none; border-bottom: 1px solid #ffeeba; }
        .recommendations li:before { content: "⚠️ "; margin-right: 10px; }
        .success-box { background-color: #d4edda; border-left: 6px solid #c3e6cb; padding: 20px; margin-bottom: 30px; border-radius: 4px; color: #155724; }
        .section-card { margin-bottom: 30px; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden; }
        .section-header { background: #34495e; color: #fff; padding: 15px; display: flex; justify-content: space-between; align-items: center; }
        .status-badge { padding: 5px 10px; border-radius: 12px; font-weight: bold; font-size: 12px; text-transform: uppercase; background-color: #3498db; color: white; }
        pre { padding: 15px; background: #f8f9fa; margin: 0; overflow-x: auto; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>Claroty CTD Best Practice Wizard Report</h1>
            <div class="meta-info">
                <span><strong>Target:</strong> $ctd_ip</span>
                <span><strong>Version:</strong> $SCRIPT_VERSION</span>
                <span><strong>Run:</strong> $current_date @ $current_time</span>
            </div>
        </div>
        <h2>1) Summary</h2>
        <div class="header-summary">
            <div>
                <p><strong>Base Version:</strong> $extracted_base_version</p>
                <p><strong>Update Version:</strong> $extracted_update_version</p>
                <p><strong>Threat Bundle:</strong> $extracted_threat_bundle</p>
                <p><strong>System Mode:</strong> $extracted_system_mode</p>
            </div>
            <div>
                <p><strong>FIPS Mode:</strong> $extracted_fips_mode</p>
                <p><strong>Zone Grouping:</strong> $extracted_zone_grouping</p>
                <p><strong>Alert Sensitivity:</strong> $extracted_alert_sensitivity</p>
                <p><strong>Assets:</strong> $extracted_assets_summary</p>
            </div>
        </div>
        <h3>Checklist Verification</h3>
        <ul>
"@)

    foreach ($chk in $checklist) {
        $null =$html_sb.AppendLine("            <li><strong>[$($chk.Status)]</strong> $($chk.Task)</li>")
    }

    $null =$html_sb.AppendLine("        </ul>`n        <h2>2) Recommendations</h2>")

    if ($actionable_insights.Count -gt 0) {
        $null = $html_sb.AppendLine('        <div class="recommendations"><ul>')
        foreach ($insight in $actionable_insights) {
            $null = $html_sb.AppendLine("            <li>$insight</li>")
        }
        $null = $html_sb.AppendLine('        </ul></div>')
    } else {
        $null = $html_sb.AppendLine('        <div class="success-box"><p><strong>System perfectly matches the Federal Golden Baseline configuration.</strong></p></div>')
    }

    $null = $html_sb.AppendLine("        <h2>3) Data</h2>")
    foreach ($metric in $report_metrics.Keys) {
        $details = $report_metrics[$metric]
        $null = $html_sb.AppendLine(@"
        <div class="section-card">
            <div class="section-header">
                <h3 style="margin:0; color:#fff;">$metric</h3>
                <span class="status-badge">$($details['status'])</span>
            </div>
            <pre>$($details['raw'])</pre>
        </div>
"@)
    }

    $null = $html_sb.AppendLine("    </div>\n</body>\n</html>")
    Set-Content -Path $html_filename -Value $html_sb.ToString() -Encoding UTF8
    Write-Host "[OK] Generated HTML: $html_filename"
}

# --- MARKDOWN OUTPUT ---
if ($selected_outputs -contains 'md') {
    $md_filename = "ctd_best_practice_report_$timestamp.md"
    $md_sb = [System.Text.StringBuilder]::new()

    $null = $md_sb.AppendLine('# Claroty CTD Best Practice Wizard Report' + "`n")
    $null = $md_sb.AppendLine('**Target Appliance:** ``' + $ctd_ip + '``  ')
    $null = $md_sb.AppendLine('**Script Version:** ``' + $SCRIPT_VERSION + '``  ')
    $null = $md_sb.AppendLine('**Audit Run:** ``' + $current_date + ' @ ' + $current_time + '``' + "`n")
    $null = $md_sb.AppendLine('---' + "`n" + '`n`n## 1) Summary' + "`n")
    $null = $md_sb.AppendLine("* **Base Version:** $extracted_base_version")
    $null = $md_sb.AppendLine("* **Update Version:** $extracted_update_version")
    $null = $md_sb.AppendLine("* **Threat Bundle:** $extracted_threat_bundle")
    $null = $md_sb.AppendLine("* **System Mode:** $extracted_system_mode")
    $null = $md_sb.AppendLine("* **FIPS Mode:** $extracted_fips_mode")
    $null = $md_sb.AppendLine("* **Zone Grouping:** $extracted_zone_grouping")
    $null = $md_sb.AppendLine("* **Alert Sensitivity:** $extracted_alert_sensitivity")
    $null = $md_sb.AppendLine("* **Assets:** $extracted_assets_summary`n")

    $null = $md_sb.AppendLine("### Checklist Verification")
    foreach ($chk in $checklist) {
        $null = $md_sb.AppendLine("* **[$($chk.Status)]** $($chk.Task)")
    }

    $null = $md_sb.AppendLine('`n---`n`n## 2) Recommendations`n')
    if ($actionable_insights.Count -gt 0) {
        foreach ($insight in $actionable_insights) {
            $null = $md_sb.AppendLine("* ⚠️ $insight")
        }
    } else {
        $null = $md_sb.AppendLine("* ✅ System perfectly matches the Federal Golden Baseline configuration. No deviations detected.")
    }

    $null = $md_sb.AppendLine('`n---`n`n## 3) Data`n')
    foreach ($metric in $report_metrics.Keys) {
        $details = $report_metrics[$metric]
        $null = $md_sb.AppendLine("### $metric")
        $null = $md_sb.AppendLine('**STATUS:** ``' + $details['status'] + '``' + "`n")
        $null = $md_sb.AppendLine('```text')
        $null = $md_sb.AppendLine($details['raw'])
        $null = $md_sb.AppendLine('```' + "`n")
    }

    Set-Content -Path $md_filename -Value $md_sb.ToString() -Encoding UTF8
    Write-Host "[OK] Generated Markdown: $md_filename"
}

# --- CSV OUTPUT ---
if ($selected_outputs -contains 'csv') {
    $csv_filename = "ctd_action_plan_$timestamp.csv"
    $csv_rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($chk in $checklist) {
        $csv_rows.Add([PSCustomObject]@{
            "Section"                 = "Summary"
            "Type"                    = "Checklist"
            "Status/Severity"         = $chk.Status
            "Finding/Task Description" = $chk.Task
        })
    }

    foreach ($insight in $actionable_insights) {
        $csv_rows.Add([PSCustomObject]@{
            "Section"                 = "Recommendations"
            "Type"                    = "Deviation Alert"
            "Status/Severity"         = "REVIEW"
            "Finding/Task Description" = $insight
        })
    }

    $csv_rows | Export-Csv -Path $csv_filename -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Generated CSV Action Plan: $csv_filename"
}

Write-Host ("=" * 70)
Write-Host "[SUCCESS] Best Practice Wizard execution sequence complete."
Write-Host ("=" * 70)