<#
=============================================================================
Script Metadata
-----------------------------------------------------------------------------
Author       : Pranjali Sanwal
Project      : Claroty CTD Best Practice Wizard
Scope        : System configuration & Troubleshooting Info
-----------------------------------------------------------------------------
PowerShell port of ctd_wizard_v11.1.py
Runs on Windows PowerShell 5.1 and PowerShell 7+ (Windows, macOS, Linux).
No modules required.

Usage:
    .\ctd_wizard_v11.1.ps1
    # If blocked by execution policy:
    powershell -ExecutionPolicy Bypass -File .\ctd_wizard_v11.1.ps1
=============================================================================
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest progress bar is very slow on 5.1

$SCRIPT_VERSION = "v11.1"

$IsModernPS = $PSVersionTable.PSVersion.Major -ge 7
$Inv        = [System.Globalization.CultureInfo]::InvariantCulture

# Suppress certificate validation for self-signed CTD certificates
if (-not $IsModernPS) {
    # Windows PowerShell 5.1: trust all certs via ServicePointManager and enable TLS 1.2
    if (-not ('CtdTrustAllCerts' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CtdTrustAllCerts {
    public static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) { return true; }
    public static void Enable() { ServicePointManager.ServerCertificateValidationCallback = Validate; }
}
"@
    }
    [CtdTrustAllCerts]::Enable()
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
# PowerShell 7+ uses -SkipCertificateCheck per request (see Invoke-CtdRequest)

# PowerShell 7.0-7.4 ConvertFrom-Json silently turns ISO date strings into local DateTime objects,
# which would break the license/threat-bundle date math. Use -DateKind String (7.5+) or raw Newtonsoft.
$JsonHasDateKind = $IsModernPS -and (Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')
if ($IsModernPS -and -not $JsonHasDateKind) { $null = ConvertFrom-Json -InputObject '{}' }  # loads Newtonsoft.Json

# =============================================================================
# HELPERS (Python-equivalent semantics for JSON handling and formatting)
# =============================================================================
function Test-IsDict($v) { $v -is [System.Management.Automation.PSCustomObject] }

function Test-HasProp($obj, [string]$name) {
    (Test-IsDict $obj) -and ($null -ne $obj.PSObject.Properties[$name])
}

# Python dict.get(name, default): default only when the key is missing (not when it is null)
function Get-Prop($obj, [string]$name, $default = $null) {
    $val = $default
    if (Test-IsDict $obj) {
        $p = $obj.PSObject.Properties[$name]
        if ($null -ne $p) { $val = $p.Value }
    }
    if ($val -is [System.Collections.IList]) { return , $val }
    return $val
}

# Python truthiness
function Test-Truthy($v) {
    if ($v -is [System.Collections.ICollection]) { return $v.Count -gt 0 }
    if ($null -eq $v) { return $false }
    if ($v -is [bool]) { return $v }
    if ($v -is [string]) { return $v.Length -gt 0 }
    if (Test-IsDict $v) { return @($v.PSObject.Properties).Count -gt 0 }
    if ($v -is [ValueType]) { try { return [double]$v -ne 0 } catch { return $true } }
    return $true
}

# Python "a or b or c": first truthy value, else the last value
function Get-FirstTruthy {
    foreach ($a in $args) { if (Test-Truthy $a) { return $a } }
    return $args[-1]
}

function Get-Count($v) {
    if ($v -is [System.Collections.ICollection]) { return $v.Count }
    if ($null -eq $v) { return 0 }
    return 1
}

# Python str(): None/True/False, floats keep ".0", culture-invariant numbers
function ConvertTo-PyStr($v) {
    if ($v -is [System.Collections.ICollection] -and $v -isnot [string]) {
        return '[' + ((@($v) | ForEach-Object { ConvertTo-PyStr $_ }) -join ', ') + ']'
    }
    if ($null -eq $v) { return 'None' }
    if ($v -is [bool]) { if ($v) { return 'True' } else { return 'False' } }
    if ($v -is [double] -or $v -is [single]) {
        $s = $v.ToString('R', $Inv)
        if ($s -match '^-?\d+$') { $s += '.0' }
        return $s
    }
    if ($v -is [System.IFormattable]) { return $v.ToString($null, $Inv) }
    return [string]$v
}

# Python f"{v:<w}"
function PadR($v, [int]$w) { (ConvertTo-PyStr $v).PadRight($w) }

# Python f"{s:^w}"
function Format-Center([string]$s, [int]$w) {
    if ($s.Length -ge $w) { return $s }
    $pad  = $w - $s.Length
    $left = [int][math]::Floor($pad / 2)
    return (' ' * $left) + $s + (' ' * ($pad - $left))
}

# Python str.title()
function ConvertTo-PyTitle([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    $prevCased = $false
    foreach ($ch in $s.ToCharArray()) {
        if ([char]::IsLetter($ch)) {
            if ($prevCased) { [void]$sb.Append([char]::ToLowerInvariant($ch)) } else { [void]$sb.Append([char]::ToUpperInvariant($ch)) }
            $prevCased = $true
        } else {
            [void]$sb.Append($ch)
            $prevCased = $false
        }
    }
    return $sb.ToString()
}

# Python float(str(v).replace('%', '')); returns $null where Python would raise
function ConvertTo-PyFloat($v) {
    $d = 0.0
    if ([double]::TryParse((ConvertTo-PyStr $v).Replace('%', ''), [System.Globalization.NumberStyles]::Float, $Inv, [ref]$d)) { return $d }
    return $null
}

# Python str(v).replace('.', '', 1).isdigit()
function Test-PyNumericString($v) {
    (ConvertTo-PyStr $v) -match '^(?:\d+\.?\d*|\.\d+)$'
}

# Python datetime.strptime(s[:10], "%Y-%m-%d").date()
function ConvertTo-PyDate($v) {
    $s = ConvertTo-PyStr $v
    $s = $s.Substring(0, [math]::Min(10, $s.Length))
    return [datetime]::ParseExact($s, 'yyyy-M-d', $Inv).Date
}

function ConvertFrom-JToken($Token) {
    if ($Token -is [Newtonsoft.Json.Linq.JObject]) {
        $o = [ordered]@{}
        foreach ($p in $Token.Properties()) { $o[$p.Name] = ConvertFrom-JToken $p.Value }
        return [pscustomobject]$o
    }
    if ($Token -is [Newtonsoft.Json.Linq.JArray]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Token) { $list.Add((ConvertFrom-JToken $i)) }
        return , $list.ToArray()
    }
    return $Token.Value
}

# Python response.json(): throws on empty / invalid JSON
function Get-Json($Response) {
    $content = $Response.Content
    if ([string]::IsNullOrWhiteSpace($content)) { throw "Expecting value: empty response body (HTTP $($Response.StatusCode))" }
    if (-not $IsModernPS) {
        $obj = ConvertFrom-Json -InputObject $content
    } elseif ($JsonHasDateKind) {
        $obj = ConvertFrom-Json -InputObject $content -NoEnumerate -DateKind String
    } else {
        $reader = New-Object Newtonsoft.Json.JsonTextReader (New-Object System.IO.StringReader $content)
        $reader.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
        $obj = ConvertFrom-JToken ([Newtonsoft.Json.Linq.JToken]::ReadFrom($reader))
    }
    if ($obj -is [System.Collections.IList]) { return , $obj }
    return $obj
}

# requests.get/post equivalent: never throws on HTTP error codes, returns StatusCode + Content
function Invoke-CtdRequest {
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Query,
        [string]$Method = 'GET',
        [hashtable]$Headers = $script:getauthheaders,
        [string]$Body,
        [int]$TimeoutSec = 15
    )
    $uri = "https://$($script:ctd_ip)$Path"
    if ($Query -and $Query.Count -gt 0) {
        $pairs = foreach ($k in $Query.Keys) { [uri]::EscapeDataString([string]$k) + '=' + [uri]::EscapeDataString([string]$Query[$k]) }
        $uri += '?' + ($pairs -join '&')
    }

    $params = @{ Uri = $uri; Method = $Method; Headers = $Headers; TimeoutSec = $TimeoutSec; UseBasicParsing = $true }
    if ($Body) { $params.Body = $Body; $params.ContentType = 'application/json' }
    if ($IsModernPS) {
        $params.SkipCertificateCheck = $true
        $params.SkipHttpErrorCheck   = $true
        $params.SkipHeaderValidation = $true
    }

    try {
        $r = Invoke-WebRequest @params
        $code = [int]$r.StatusCode
        $content = $r.Content
    } catch [System.Net.WebException] {
        # Windows PowerShell 5.1 throws on non-2xx; recover the status code and body
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $code = [int]$resp.StatusCode
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        try { $content = $sr.ReadToEnd() } finally { $sr.Dispose() }
    }
    if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
    return [pscustomobject]@{ StatusCode = $code; Content = [string]$content }
}

# Python ipaddress semantics: ip_network(s, strict=False) -> not is_private and not is_link_local
$PrivateNetworksV4   = @('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/29',
                         '192.0.0.170/31', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
                         '203.0.113.0/24', '240.0.0.0/4', '255.255.255.255/32')
$PrivateExceptionsV4 = @('192.0.0.9/32', '192.0.0.10/32')
$PrivateNetworksV6   = @('::1/128', '::/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
                         '2001:db8::/32', '2001:10::/28', 'fc00::/7', 'fe80::/10')
$PrivateExceptionsV6 = @('2001:1::1/128', '2001:1::2/128', '2001:3::/32', '2001:4:112::/48', '2001:20::/28', '2001:30::/28')

function Get-ByteMask([int]$prefixLen, [int]$byteIndex) {
    $bitsHere = [math]::Max(0, [math]::Min(8, $prefixLen - 8 * $byteIndex))
    if ($bitsHere -eq 0) { return 0 }
    return (0xFF -shl (8 - $bitsHere)) -band 0xFF
}

function ConvertTo-IpBytes([string]$s) {
    $ip = $null
    if ($s.Contains(':')) {
        if (-not [System.Net.IPAddress]::TryParse($s, [ref]$ip)) { return $null }
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
    } else {
        # Strict dotted quad, no leading zeros (Python rejects them; .NET would read them as octal)
        if ($s -notmatch '^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$') { return $null }
        if (-not [System.Net.IPAddress]::TryParse($s, [ref]$ip)) { return $null }
    }
    return , $ip.GetAddressBytes()
}

function Test-IpInCidr([byte[]]$ip, [string]$cidr) {
    $parts = $cidr.Split('/')
    $net = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    $len = [int]$parts[1]
    if ($net.Length -ne $ip.Length) { return $false }
    for ($i = 0; $i -lt $ip.Length; $i++) {
        $m = Get-ByteMask $len $i
        if (($ip[$i] -band $m) -ne ($net[$i] -band $m)) { return $false }
    }
    return $true
}

function Test-IpIsPrivate([byte[]]$ip) {
    if ($ip.Length -eq 4) { $nets = $PrivateNetworksV4; $excl = $PrivateExceptionsV4 }
    else                  { $nets = $PrivateNetworksV6; $excl = $PrivateExceptionsV6 }
    $inPrivate = $false
    foreach ($c in $nets) { if (Test-IpInCidr $ip $c) { $inPrivate = $true; break } }
    if (-not $inPrivate) { return $false }
    foreach ($c in $excl) { if (Test-IpInCidr $ip $c) { return $false } }
    return $true
}

# Returns $true / $false, or $null when Python's ip_network() would raise ValueError
function Test-NetworkIsPrivate([string]$cidr) {
    $parts = $cidr.Split('/')
    if ($parts.Count -gt 2) { return $null }
    $addr = ConvertTo-IpBytes $parts[0]
    if ($null -eq $addr) { return $null }
    $bits = $addr.Length * 8

    if ($parts.Count -eq 1) {
        $len = $bits
    } elseif ($parts[1] -match '^\d+$') {
        $len = [int]$parts[1]
        if ($len -gt $bits) { return $null }
    } elseif ($addr.Length -eq 4) {
        # IPv4 netmask (255.255.255.0) or hostmask (0.0.0.255)
        $m = ConvertTo-IpBytes $parts[1]
        if ($null -eq $m -or $m.Length -ne 4) { return $null }
        $maskInt = ([uint32]$m[0] -shl 24) -bor ([uint32]$m[1] -shl 16) -bor ([uint32]$m[2] -shl 8) -bor [uint32]$m[3]
        $len = $null
        foreach ($candidate in @($maskInt, ([uint32]::MaxValue -bxor $maskInt))) {
            $ones = 0
            while ($ones -lt 32 -and ($candidate -band ([uint32]1 -shl (31 - $ones))) -ne 0) { $ones++ }
            $expected = if ($ones -eq 0) { [uint64]0 } else { ([uint64]4294967295 -shl (32 - $ones)) -band [uint64]4294967295 }
            if ($candidate -eq $expected) { $len = $ones; break }
        }
        if ($null -eq $len) { return $null }
    } else {
        return $null
    }

    $first = New-Object byte[] $addr.Length
    $last  = New-Object byte[] $addr.Length
    for ($i = 0; $i -lt $addr.Length; $i++) {
        $m = Get-ByteMask $len $i
        $first[$i] = $addr[$i] -band $m
        $last[$i]  = $first[$i] -bor ((-bnot $m) -band 0xFF)
    }
    return (Test-IpIsPrivate $first) -and (Test-IpIsPrivate $last)
}

# =============================================================================
# SYSTEM DEFAULTS & BASELINES (Hardcoded from Default_Data.json)
# =============================================================================
$DEFAULT_CONFIG = @{
    fips_enabled           = $false
    training_mode          = $true
    max_ram_pct            = 80.0
    max_cpu_pct            = 80.0
    max_disk_pct           = 80.0
    require_span_interface = $true
}

# Case-sensitive lookup to match Python dict semantics
$DEFAULT_PROTOCOLS = New-Object 'System.Collections.Generic.Dictionary[string,bool]' ([StringComparer]::Ordinal)
$defaultProtocolTable = @{
    'honeywell.Firewall' = $true
    'cclink_ie.cclink_ie_field' = $true
    'fortinet_discovery' = $true
    'toshiba_tcnet' = $true
    'terasaki.layer_2_broadcast' = $true
    'rapienet' = $false
    'rpc' = $true
    'dns' = $true
    'ssh' = $true
    'dhcp' = $true
    'ftp' = $true
    'ftp_data' = $true
    'http' = $true
    'icmp' = $true
    'igmp' = $true
    'modbus.tcp' = $true
    'browser' = $true
    'arp' = $true
    'cip' = $true
    'enip' = $true
    's7comm' = $true
    'profinet.dcp' = $true
    'llc' = $true
    'lldp' = $true
    'dcerpc' = $true
    'mms' = $true
    'tftp' = $true
    'profinet.pn_io' = $true
    'ntp' = $true
    'opc_ua' = $true
    'nbdgm' = $true
    'ntlmssp' = $true
    'samr' = $true
    'vnc' = $true
    'ssl' = $true
    's7commplus' = $true
    'cotp' = $true
    'smb' = $true
    'smb_pipe' = $true
    'lanman' = $true
    'atsvc' = $true
    'srvsvc' = $true
    'rdp' = $true
    'ge_srtp' = $true
    'goose' = $true
    'egd' = $true
    'roc_plus' = $true
    'bnc' = $true
    'ge_sdi' = $true
    'ge_sdiclassic' = $true
    'ge_quickpanel' = $true
    'foxboro' = $true
    'ff' = $false
    'honeywell.FtebCipMsg' = $false
    'honeywell.PsCdaCeeNtComm' = $false
    'ldap' = $false
    'kerberos' = $false
    'rlogin' = $false
    'smtp' = $false
    'pop' = $false
    'imap' = $false
    'honeywell.PsCdaCeeNtPeer' = $false
    'hart_ip' = $false
    'telnet' = $false
    'totalflow' = $false
    'bacnet' = $false
    'ovation' = $false
    'fwl_load' = $false
    'symphony_plus' = $false
    'pinet.pi1' = $false
    'pinet.pi3' = $true
    'iec104' = $false
    'rcdp' = $true
    'eterra' = $false
    'eterra_workstation' = $false
    'abb_dms' = $false
    'red_lion' = $true
    'synchrophasor' = $true
    'mqtt' = $true
    'citect' = $true
    'keyence.keyence_kv_studio' = $true
    'profinet.rt' = $true
    'beckhoff' = $true
    'tpkt' = $true
    'portmapper' = $true
    'hsrp' = $true
    'cpha' = $true
    'rtcp' = $true
    'ge_enervista' = $false
    'epm' = $true
    'sel' = $true
    'sip' = $true
    'skinny' = $true
    'radius' = $true
    'capwap_control' = $true
    'capwap_data' = $true
    'wlan' = $true
    'hp_switch' = $true
    'ptp' = $true
    'abb_melody' = $true
    'factorytalk_rna' = $true
    'valmet_dna.damatic_configuration' = $true
    'sampled_values' = $true
    'cspv4' = $true
    'hirschmann' = $true
    'digi_real_port' = $true
    'ethercat' = $true
    'mdns' = $true
    'llmnr' = $true
    'icmpv6' = $true
    'nbns' = $true
    'h1' = $true
    'bittorrent' = $true
    'fins.tcp' = $true
    'melsec' = $true
    'ovation.ovationrpc' = $true
    'red_lion.red_lion_discovery' = $true
    'tridium_fox' = $true
    'sattbus' = $true
    'vnet.odeq' = $true
    'vnet' = $true
    'vnet.vhf' = $true
    'ovation.alarm' = $true
    'modbus.serial' = $true
    'proconos' = $true
    'tsaa' = $true
    'tristation' = $true
    'axe' = $true
    'deltav.device_connection' = $true
    'deltav.RtProgLog' = $true
    'deltav.FlashDownload' = $true
    'omniflow' = $true
    'dnp3' = $true
    'egd_cmp' = $true
    'p2' = $false
    'ovation.dbxmit' = $false
    'ovation.ptedit' = $false
    'honeywell.comm_setup' = $false
    'honeywell.EpicMo' = $false
    'opto' = $false
    'opto_mmp' = $false
    'lantronix' = $false
    'cti' = $false
    'bailey.tcp' = $false
    'bailey.serial' = $false
    'ge_alm' = $true
    'prosoft_discovery' = $true
    'iec101' = $false
    'bailey.infininet' = $false
    'secsgem' = $false
    'dacp' = $false
    'iec103' = $false
    'keyence.keyence_log_reporter' = $true
    'cognex_discovery' = $true
    'kongsberg' = $true
    'portwell' = $true
    'ovation.admd' = $false
    'mndp' = $true
    'siprotec' = $true
    'keyence.keyencehostlink' = $false
    'foxboro_rtv' = $true
    'knapp' = $true
    'linux_ha' = $true
    'comtrol_ns_link' = $true
    'slmp' = $true
    'melsoft' = $true
    'wonderware.iotalk' = $true
    'altus.alnet' = $true
    'alspa' = $true
    'schneider_netmanage' = $true
    'bnr.ina2000' = $true
    'mdlc.mdlc_management' = $true
    'mdlc.mdlc_data' = $true
    'caterpillar.gw_to_vims' = $false
    'caterpillar.hmi_to_gw' = $false
    'wsd' = $true
    'abb_dcs.rnrp' = $true
    'cygnet' = $false
    'enhanced_modbus' = $true
    'java.jrmi' = $true
    'java.java_rpc' = $true
    't3000.automation_server_data' = $true
    't3000.gw_discover' = $true
    'nmea_0183' = $true
    'opto_softpac_agent' = $false
    'honeywell.safety_manager' = $true
    'honeywell.dsa_discovery' = $true
    'iq3' = $true
    'valmet_dna.valmet_dna_data' = $true
    'valmet_dna.valmet_dna_frontend' = $false
    'valmet_dna.valmet_dna_alarms' = $true
    'wudo' = $true
    'sentinel_srm' = $true
    'valmet_dna.damatic_data' = $true
    'bsap' = $true
    'clear_scada' = $true
    'matrikon_opc' = $true
    'sbus' = $true
    'moxa_udp' = $true
    'schneider_ion' = $true
    'ethernet_powerlink' = $true
    'trdp.trdp_pd' = $true
    'koyo' = $true
    'xpact.xpact_data' = $true
    'xpact.xpact_discovery' = $true
    'xpact.xpact_diagnostics' = $true
    'cola_a' = $true
    'zabbix.zabbix_agent' = $true
    'zabbix.zabbix_sender' = $true
    'sinaut_fw8' = $false
    'ttsac' = $true
    'ge_ifix' = $true
    'wago' = $true
    'siemens_iem' = $true
    'max_dna' = $false
    'codesysv3' = $true
    'xg5000' = $true
    'flnet' = $true
    'pf_dcp' = $true
    'gaz_modem' = $true
    'codesysv2' = $true
    'dlms_cosem' = $true
    'b32' = $false
    'snmp' = $true
    'pcwin' = $false
    'tds' = $true
    'mitsubishi_got' = $true
    'jrc_vessel_display' = $true
    'focas' = $true
    'gcode' = $false
    'exi3000.discovery' = $false
    'exi3000.mgmt' = $false
    'meggitt.vibrometer' = $true
    'abb_netconfig' = $true
    'fins.udp' = $true
    'terasaki.negotiation' = $true
    'terasaki.realtime_data_sync' = $false
    'siemens_cargo.cargo_compact' = $true
    'siemens_cargo.cargo_compact_sensor' = $false
    'siemens_cargo.cargo_compact_control' = $false
    'smiths_detection.broadcast' = $true
    'mdlc.mdlc_proprietary' = $false
    'telvent.oasys' = $false
}
foreach ($k in $defaultProtocolTable.Keys) { $DEFAULT_PROTOCOLS[$k] = $defaultProtocolTable[$k] }

# Date and time calculations
$now = Get-Date
$current_date = $now.ToString('MM/dd/yyyy', $Inv)

# Force abbreviation for environments (like Windows) that return long strings
$tzInfo = [TimeZoneInfo]::Local
$tz_raw = if ($tzInfo.IsDaylightSavingTime($now)) { $tzInfo.DaylightName } else { $tzInfo.StandardName }
$tz_abbr = if ($tz_raw.Length -gt 5) { -join ($tz_raw.ToCharArray() | Where-Object { [char]::IsUpper($_) }) } else { $tz_raw }
$current_time = "$($now.ToString('HH:mm:ss', $Inv)) $tz_abbr"

$timestamp = $now.ToString('yyyyMMdd_HHmmss', $Inv)

Write-Host ('=' * 70)
Write-Host "   Claroty CTD Best Practice Wizard - Master Collector $SCRIPT_VERSION"
Write-Host ('=' * 70)

# CTD Server Info (Interactive Input)
$ctd_ip   = (Read-Host 'Enter CTD IP or hostname').Trim()
$username = (Read-Host 'Enter CTD username').Trim()
$securePassword = Read-Host 'Enter CTD password' -AsSecureString
$password = (New-Object System.Net.NetworkCredential('', $securePassword)).Password.Trim()

# Authentication Setup
$auth = [ordered]@{ username = $username; password = $password } | ConvertTo-Json -Compress
$authHeaders = @{ 'Accept' = 'application/json' }   # Content-Type is set by Invoke-CtdRequest for bodies

Write-Host "`n[*] Authenticating with Claroty CTD at $ctd_ip..."
try {
    $doauth = Invoke-CtdRequest -Method POST -Path '/auth/authenticate' -Headers $authHeaders -Body $auth -TimeoutSec 15
    $check_user_pass = Get-Json $doauth
} catch {
    Write-Host "Connection Error during authentication: $($_.Exception.Message)"
    exit 1
}

if (-not (Test-IsDict $check_user_pass) -or -not (Test-Truthy (Get-Prop $check_user_pass 'token'))) {
    Write-Host "Authentication Failed. No token received. $($doauth.Content)"
    exit 1
}

Write-Host 'Successful Login'

$ctd_auth_token = [string](Get-Prop $check_user_pass 'token')
$getauthheaders = @{ 'Authorization' = $ctd_auth_token; 'Accept' = 'application/json' }

# Dictionaries and lists to track report output
$report_metrics      = [ordered]@{}
$actionable_insights = New-Object System.Collections.Generic.List[string]

# Global variables for Header System Summary
$extracted_base_version      = 'Unknown'
$extracted_update_version    = 'Unknown'
$extracted_threat_bundle     = 'Unknown'
$extracted_system_mode       = 'Unknown'
$extracted_fips_mode         = 'Unknown'
$extracted_zone_grouping     = 'Unknown'
$extracted_alert_sensitivity = 'Unknown'
$extracted_assets_summary    = 'Total: N/A | IT: N/A | OT: N/A | IoT: N/A'

# =============================================================================
# 1. AUDIT: Remote CTD Server System Health Dashboard
# =============================================================================
Write-Host '[*] Fetching Metric: Remote System Health Dashboard...'
try {
    $health_res = Invoke-CtdRequest -Path '/ranger/system_health'
    if ($health_res.StatusCode -ne 200) {
        $health_res = Invoke-CtdRequest -Path '/ranger/ranger_api/system_health'
    }

    $cpu_pct = 'N/A'; $ram_pct = 'N/A'
    $partitions_summary = [ordered]@{}
    $assessment_status = 'REVIEW'

    if ($health_res.StatusCode -eq 200) {
        $payload = Get-Json $health_res
        $data_block = if (Test-IsDict $payload) { Get-Prop $payload 'data' } else { $null }

        $site_data = $null
        if (Test-IsDict $data_block) {
            foreach ($prop in $data_block.PSObject.Properties) {
                if ((Test-IsDict $prop.Value) -and (Test-HasProp $prop.Value 'factors')) {
                    $site_data = $prop.Value
                    break
                }
            }
        }

        $factors = Get-Prop $site_data 'factors'
        $system_factor = $null

        if (Test-IsDict $factors) {
            $app_health = Get-Prop $factors 'application_health'
            if (Test-IsDict $app_health) {
                $system_factor = Get-Prop $app_health 'system_status'
            } else {
                $system_factor = Get-Prop $factors 'system_status'
            }
        } elseif ($factors -is [System.Collections.IList]) {
            foreach ($f in $factors) {
                if ((Test-IsDict $f) -and ((Get-Prop $f 'type') -ceq 'system_status')) { $system_factor = $f; break }
            }
        }

        if (Test-IsDict $system_factor) {
            $info_block = Get-Prop $system_factor 'info'
            $sys_status = Get-Prop $info_block 'system_status'

            $raw_cpu_data = Get-Prop $sys_status 'cpu'
            $raw_cpu = if (Test-IsDict $raw_cpu_data) { Get-Prop $raw_cpu_data 'value' } else { $raw_cpu_data }
            $raw_ram_data = Get-Prop $sys_status 'memory'
            $raw_ram = if (Test-IsDict $raw_ram_data) { Get-Prop $raw_ram_data 'value' } else { $raw_ram_data }

            if ($null -ne $raw_cpu) { $cpu_pct = if (Test-PyNumericString $raw_cpu) { "$(ConvertTo-PyStr $raw_cpu)%" } else { ConvertTo-PyStr $raw_cpu } }
            if ($null -ne $raw_ram) { $ram_pct = if (Test-PyNumericString $raw_ram) { "$(ConvertTo-PyStr $raw_ram)%" } else { ConvertTo-PyStr $raw_ram } }

            $cpu_float = 0.0
            $ram_float = 0.0

            $parsed_ram = ConvertTo-PyFloat $raw_ram
            if ($null -ne $parsed_ram) {
                $ram_float = $parsed_ram
                $parsed_cpu = ConvertTo-PyFloat $raw_cpu
                if ($null -ne $parsed_cpu) {
                    $cpu_float = $parsed_cpu
                    $max_ram = $DEFAULT_CONFIG.max_ram_pct
                    $max_cpu = $DEFAULT_CONFIG.max_cpu_pct

                    if ($ram_float -gt $max_ram) {
                        $actionable_insights.Add("Server Health: Server Memory ($ram_pct) exceeds the baseline threshold of $(ConvertTo-PyStr $max_ram)%.")
                    }
                    if ($cpu_float -gt $max_cpu) {
                        $actionable_insights.Add("Server Health: Server CPU ($cpu_pct) exceeds the baseline threshold of $(ConvertTo-PyStr $max_cpu)%.")
                    }
                }
            }

            $disk_block = Get-Prop $sys_status 'disk'
            $display_names = @{ os = 'OS (/)'; data = 'Data (/var)'; logs = 'Logs (/var/log)'; temp = 'Temp (/tmp)'; audit = 'Audit (/var/log/audit)' }

            $max_disk = $DEFAULT_CONFIG.max_disk_pct
            $disk_violation = $false

            if (Test-IsDict $disk_block) {
                foreach ($prop in $disk_block.PSObject.Properties) {
                    $key = $prop.Name
                    $part = $prop.Value
                    if (Test-IsDict $part) {
                        $part_name = if ($display_names.ContainsKey($key)) { $display_names[$key] } else { "Partition ($key)" }
                        if (Test-HasProp $part 'percentage') {
                            $pct = Get-Prop $part 'percentage'
                        } elseif ((Get-Prop $part 'total' 0) -gt 0) {
                            $pct = [math]::Round(([double](Get-Prop $part 'used' 0) / [double](Get-Prop $part 'total')) * 100, 2)
                        } else {
                            $pct = $null
                        }
                        if ($null -ne $pct) {
                            $partitions_summary[$part_name] = if ($pct -gt 0 -and $pct -lt 0.1) { '<0.1%' } else { "$(ConvertTo-PyStr $pct)%" }
                            if ($pct -gt $max_disk) {
                                $actionable_insights.Add("Server Health: Storage $part_name ($(ConvertTo-PyStr $pct)%) exceeds the baseline threshold of $(ConvertTo-PyStr $max_disk)%.")
                                $disk_violation = $true
                            }
                        }
                    }
                }
            }

            $assessment_status = if ($ram_float -le $DEFAULT_CONFIG.max_ram_pct -and $cpu_float -le $DEFAULT_CONFIG.max_cpu_pct -and -not $disk_violation) { 'PASS' } else { 'REVIEW' }
        }
    }

    if ($partitions_summary.Count -eq 0) { $partitions_summary = [ordered]@{ 'Error' = 'No storage partitions parsed.' } }

    $health_table = @(('=' * 50), "$(PadR 'METRIC' 25) | VALUE", ('-' * 50))
    $health_table += "$(PadR 'Server CPU' 25) | $cpu_pct"
    $health_table += "$(PadR 'Server Memory' 25) | $ram_pct"
    $health_table += ('-' * 50)
    $health_table += 'STORAGE PARTITIONS'
    foreach ($k in $partitions_summary.Keys) {
        $health_table += "$(PadR $k 25) | $($partitions_summary[$k])"
    }
    $health_table += ('=' * 50)

    $report_metrics['System Health Summary'] = @{ status = $assessment_status; raw = ($health_table -join "`n") }
} catch {
    $report_metrics['System Health Summary'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# 2. AUDIT: License Status
# =============================================================================
Write-Host '[*] Fetching Metric: System License Status...'
try {
    $lic_res = Invoke-CtdRequest -Path '/ranger/license' -Query @{ site_id = '1' }
    $lic_data = Get-Json $lic_res

    if ((Test-IsDict $lic_data) -and ((Get-Prop $lic_data 'success') -eq $true)) {
        $lic_inner = Get-Prop $lic_data 'data'
        $status_color = (ConvertTo-PyStr (Get-Prop $lic_inner 'status' 'unknown')).ToLowerInvariant()
        $is_fips = Get-Prop $lic_inner 'is_fips' $false
        $exp_date_str = Get-Prop $lic_inner 'expiration_date'

        $assessment_status = if ($status_color -ceq 'green') { 'PASS' } else { 'FAIL' }

        $extracted_fips_mode = if (Test-Truthy $is_fips) { 'Yes' } else { 'No' }
        $days_left_str = 'N/A'

        if (Test-Truthy $exp_date_str) {
            $exp_date = ConvertTo-PyDate $exp_date_str
            $days_left = ($exp_date - (Get-Date).Date).Days
            $days_left_str = "$days_left remaining"
            if ($days_left -le 14) {
                $assessment_status = 'REVIEW'
                $actionable_insights.Add("License: License expires in $days_left days. Recommend requesting a new license.")
            }
        }

        $status_display = if ($status_color.Length -gt 0) { $status_color.Substring(0, 1).ToUpperInvariant() + $status_color.Substring(1) } else { '' }

        $lic_table = @(('=' * 60), "$(PadR 'LICENSE ATTRIBUTE' 25) | VALUE", ('-' * 60))
        $lic_table += "$(PadR 'Status' 25) | $status_display"
        $lic_table += "$(PadR 'FIPS Mode' 25) | $(ConvertTo-PyStr $is_fips)"
        $lic_table += "$(PadR 'Expiration Date' 25) | $(ConvertTo-PyStr $exp_date_str)"
        $lic_table += "$(PadR 'Days Remaining' 25) | $days_left_str"
        $lic_table += ('=' * 60)

        $report_metrics['License Status'] = @{ status = $assessment_status; raw = ($lic_table -join "`n") }
    } else {
        $report_metrics['License Status'] = @{ status = 'ERROR'; raw = 'Failed to parse license data.' }
    }
} catch {
    $report_metrics['License Status'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# 3. AUDIT: Virtual Zones List
# =============================================================================
Write-Host '[*] Fetching Metric: Virtual Zone Allocations...'
try {
    $zone_res = Invoke-CtdRequest -Path '/ranger/virtual_zones'
    $zone_data = Get-Json $zone_res

    if (Test-HasProp $zone_data 'objects') {
        $zone_objects = Get-Prop $zone_data 'objects'
        $zone_count = Get-Count $zone_objects
        $assessment_status = if ($zone_count -gt 0) { 'PASS' } else { 'REVIEW' }

        $zt_lines = @(('=' * 80), "$(PadR 'ID' 5) | $(PadR 'ZONE NAME' 35) | $(PadR 'CRITICALITY' 15) | ASSETS", ('-' * 80))
        foreach ($z in $zone_objects) {
            $z_crit = (ConvertTo-PyStr (Get-Prop $z 'criticality__' 'Unknown')).Replace('e', '')
            $zt_lines += "$(PadR (Get-Prop $z 'id' '') 5) | $(PadR (Get-Prop $z 'name' '') 35) | $(PadR $z_crit 15) | $(ConvertTo-PyStr (Get-Prop $z 'num_assets' 0))"
        }
        $zt_lines += ('=' * 80)

        $report_metrics['Virtual Zones List'] = @{ status = $assessment_status; raw = ($zt_lines -join "`n") }
    } else {
        $report_metrics['Virtual Zones List'] = @{ status = 'ERROR'; raw = 'No zone data found.' }
    }
} catch {
    $report_metrics['Virtual Zones List'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# 4. AUDIT: Subnet Table Summary
# =============================================================================
Write-Host '[*] Fetching Metric: Formatted Subnet Table...'
try {
    $subnet_params = [ordered]@{ sort = 'name'; page = '1'; per_page = '50'; with_assets__exact = 'true'; site_id__exact = '1'; distinct = 'false' }

    $subnet_res = Invoke-CtdRequest -Path '/ranger/subnets' -Query $subnet_params
    $subnet_data = Get-Json $subnet_res
    $subnet_objects = Get-Prop $subnet_data 'objects'

    if ((Test-HasProp $subnet_data 'objects') -and (Test-Truthy $subnet_objects)) {
        $table_lines = @(('=' * 80), "$(PadR '#' 3) | $(PadR 'SUBNET IP' 18) | $(PadR 'NETWORK' 15) | $(PadR 'TYPE' 12) | ASSETS", ('-' * 80))
        $count = 0
        foreach ($item in $subnet_objects) {
            $count++
            $subnet_ip = Get-FirstTruthy (Get-Prop $item 'name') (Get-Prop $item 'subnet') 'Unknown'
            $network   = Get-FirstTruthy (Get-Prop $item 'network_name') (Get-Prop $item 'network') 'N/A'
            $assets    = Get-FirstTruthy (Get-Prop $item 'num_assets') (Get-Prop $item 'assets_count') 0
            $raw_type  = Get-Prop $item 'type'
            if ($null -ne $raw_type) {
                # TYPE_MAPPING = {0: "Internal", 1: "External"}
                if     ($raw_type -is [ValueType] -and $raw_type -eq 0) { $subnet_type = 'Internal' }
                elseif ($raw_type -is [ValueType] -and $raw_type -eq 1) { $subnet_type = 'External' }
                else   { $subnet_type = "Type $(ConvertTo-PyStr $raw_type)" }
            } else {
                $subnet_type = Get-FirstTruthy (Get-Prop $item 'subnet_type') 'N/A'
            }

            # WIZARD CHECK: Subnets - RFC-1918 addresses only
            if ((Test-Truthy $subnet_ip) -and ($subnet_ip -cne 'Unknown')) {
                $is_private = Test-NetworkIsPrivate (ConvertTo-PyStr $subnet_ip)
                if ($is_private -eq $false) {
                    $actionable_insights.Add("Subnets: RFC-1918 addresses only; ensure no public IPs used internally (Flagged: $(ConvertTo-PyStr $subnet_ip))")
                }
            }

            $table_lines += "$(PadR $count 3) | $(PadR $subnet_ip 18) | $(PadR $network 15) | $(PadR $subnet_type 12) | $(ConvertTo-PyStr $assets)"
        }
        $table_lines += ('=' * 80)
        $report_metrics['Subnet Table Summary'] = @{ status = 'PASS'; raw = ($table_lines -join "`n") }
    } else {
        $report_metrics['Subnet Table Summary'] = @{ status = 'REVIEW'; raw = 'No subnet data objects found.' }
    }
} catch {
    $report_metrics['Subnet Table Summary'] = @{ status = 'ERROR'; raw = "Error formatting subnet table: $($_.Exception.Message)" }
}

# =============================================================================
# 5. AUDIT: System Versions, Updates & Threat Bundles
# =============================================================================
Write-Host '[*] Fetching Metric: System Versions & Threat Bundles...'
try {
    $base_res   = Invoke-CtdRequest -Path '/ranger/current_version' -Query @{ ids = '1' }
    $update_res = Invoke-CtdRequest -Path '/ranger/current_update_version' -Query @{ site_id = '1' }
    $bundle_res = Invoke-CtdRequest -Path '/ranger/ranger_api/last_date_of_update' -Query @{ site_id__exact = '1' }

    if ($base_res.StatusCode -eq 200) {
        $bv_data = Get-Prop (Get-Json $base_res) 'data'
        if (Test-IsDict $bv_data) {
            foreach ($prop in $bv_data.PSObject.Properties) {
                if (Test-HasProp $prop.Value 'response') {
                    $extracted_base_version = ConvertTo-PyStr (Get-Prop $prop.Value 'response')
                    break
                }
            }
        }
    }

    if ($update_res.StatusCode -eq 200) {
        $u_data = Get-Prop (Get-Json $update_res) 'data'
        if (Test-IsDict $u_data) {
            $extracted_update_version = ConvertTo-PyStr (Get-Prop $u_data 'update_version' 'Unknown')
        }
    }

    # WIZARD CHECK: No version update reported
    if (@('Unknown', 'None', '', '0') -ccontains $extracted_update_version) {
        $actionable_insights.Add('Version: No version update reported means none applied; suggested applying latest available update.')
    }

    if ($bundle_res.StatusCode -eq 200) {
        $b_data = Get-Prop (Get-Json $bundle_res) 'data'
        if (Test-IsDict $b_data) {
            $extracted_threat_bundle = ConvertTo-PyStr (Get-Prop $b_data 'bundle_id' 'Unavailable')
            $last_issue_str = Get-Prop $b_data 'last_date_of_issue'

            # WIZARD CHECK: Threat Bundle update > 30 days
            if (Test-Truthy $last_issue_str) {
                try {
                    $issue_date = ConvertTo-PyDate $last_issue_str
                    $days_old = ((Get-Date).Date - $issue_date).Days
                    if ($days_old -gt 30) {
                        $actionable_insights.Add("Threat Bundle: Threat Bundle update > 30 days ($days_old days old). Check for a newer version.")
                    }
                } catch { }
            }
        }
    }
} catch { }

# =============================================================================
# 6. AUDIT: System Mode
# =============================================================================
Write-Host '[*] Fetching Metric: CTD Operational Mode...'
try {
    $mode_params = [ordered]@{ format = 'site_list_slim'; sort = 'name'; page = '1'; per_page = '0' }
    $mode_res = Invoke-CtdRequest -Path '/ranger/sites' -Query $mode_params
    $mode_data = Get-Json $mode_res
    $mode_objects = Get-Prop $mode_data 'objects'

    if ((Test-HasProp $mode_data 'objects') -and (Test-Truthy $mode_objects)) {
        $live_training_mode = Get-Prop $mode_objects[0] 'training_mode'
        $extracted_system_mode = if (Test-Truthy $live_training_mode) { 'Training' } else { 'Operational' }

        # WIZARD CHECK: Training mode
        if (Test-Truthy $live_training_mode) {
            $actionable_insights.Add("System Mode: Training mode $([char]0x2013) Behavioral threat detection not possible.")
        }
    }
} catch { }

# =============================================================================
# 7. AUDIT: Virtual Zone Grouping Algorithm
# =============================================================================
$GUI_MAPPINGS = @{
    'default' = 'Default Behavioral Grouping Algorithm'
    'purdue'  = 'Purdue Model Grouping'
    'network' = 'Network Subnet Grouping'
    'custom'  = 'Custom Grouping Algorithm'
}

function Find-Grouping($data) {
    if (Test-IsDict $data) {
        foreach ($key in @('algorithm', 'grouping_algorithm', 'name', 'value', 'method')) {
            if ((Test-HasProp $data $key) -and (Test-Truthy (Get-Prop $data $key))) {
                $raw = ConvertTo-PyStr (Get-Prop $data $key)
                $raw_val = $raw.ToLowerInvariant()
                if ($GUI_MAPPINGS.ContainsKey($raw_val)) { return $GUI_MAPPINGS[$raw_val] }
                return ConvertTo-PyTitle $raw
            }
        }
        foreach ($prop in $data.PSObject.Properties) {
            $res = Find-Grouping $prop.Value
            if (Test-Truthy $res) { return $res }
        }
    } elseif ($data -is [System.Collections.IList]) {
        foreach ($entry in $data) {
            $res = Find-Grouping $entry
            if (Test-Truthy $res) { return $res }
        }
    }
    return $null
}

Write-Host '[*] Fetching Metric: Virtual Zone Grouping Algorithm...'
try {
    $vz_res = Invoke-CtdRequest -Path '/ranger/virtual_zones_grouping_algorithm' -Query @{ site_id = '1' }
    if ($vz_res.StatusCode -eq 200) {
        $vz_data = Get-Json $vz_res
        $extracted = Find-Grouping $vz_data
        if (Test-Truthy $extracted) { $extracted_zone_grouping = $extracted }
    }
} catch { }

# =============================================================================
# 8. AUDIT: Alert Sensitivity
# =============================================================================
function Find-Sensitivity($data) {
    if (Test-IsDict $data) {
        foreach ($key in @('alerts_threshold', 'sensitivity', 'alert_sensitivity', 'level', 'score_config')) {
            if ((Test-HasProp $data $key) -and ($null -ne (Get-Prop $data $key))) {
                return ConvertTo-PyTitle (ConvertTo-PyStr (Get-Prop $data $key))
            }
        }
        foreach ($prop in $data.PSObject.Properties) {
            $res = Find-Sensitivity $prop.Value
            if (Test-Truthy $res) { return $res }
        }
    } elseif ($data -is [System.Collections.IList]) {
        foreach ($entry in $data) {
            $res = Find-Sensitivity $entry
            if (Test-Truthy $res) { return $res }
        }
    }
    return $null
}

Write-Host '[*] Fetching Metric: Alert Sensitivity...'
try {
    $alert_res = Invoke-CtdRequest -Path '/ranger/alerts/score_config' -Query @{ site_id = '1' } -TimeoutSec 10
    if ($alert_res.StatusCode -eq 200) {
        $alert_data = Get-Json $alert_res

        if (Test-HasProp $alert_data 'alerts_threshold') {
            $extracted_alert_sensitivity = ConvertTo-PyStr (Get-Prop $alert_data 'alerts_threshold')
        } else {
            $ext_sens = Find-Sensitivity $alert_data
            if (Test-Truthy $ext_sens) { $extracted_alert_sensitivity = $ext_sens }
        }
    }
} catch { }

# =============================================================================
# 9. AUDIT: Asset Counts & Categorization Breakdown
# =============================================================================
function Get-CtdAssetCount($ClassType, [int]$TimeoutSec) {
    $params = [ordered]@{
        format                 = 'asset_list'
        ghost__exact           = 'false'
        special_hint__exact    = '0'
        insight_status__exact  = '0'
        site_id__exact         = '1'
        last_seen__gte         = $script:one_year_ago
        count_only             = 'true'
    }
    if ($null -ne $ClassType) { $params['class_type__exact'] = $ClassType }
    $res = Invoke-CtdRequest -Path '/ranger/assets' -Query $params -TimeoutSec $TimeoutSec
    if ($res.StatusCode -ne 200) { return 0 }
    $j = Get-Json $res
    return Get-Prop $j 'count_total' (Get-Prop $j 'total' 0)
}

Write-Host '[*] Fetching Metric: Asset Summary Breakdown...'
try {
    $one_year_ago = (Get-Date).ToUniversalTime().AddDays(-365).ToString("yyyy-MM-dd'T'00:00:00.000'Z'", $Inv)

    $total_a = Get-CtdAssetCount $null 15
    $it_a    = Get-CtdAssetCount '1' 10
    $ot_a    = Get-CtdAssetCount '0' 10
    $iot_a   = Get-CtdAssetCount '2' 10

    $extracted_assets_summary = "Total: $(ConvertTo-PyStr $total_a) | IT: $(ConvertTo-PyStr $it_a) | OT: $(ConvertTo-PyStr $ot_a) | IoT: $(ConvertTo-PyStr $iot_a)"
} catch { }

# =============================================================================
# 10. AUDIT: Collection Methods & Sensors
# =============================================================================
Write-Host '[*] Fetching Metric: Connected Collection Sensors Health...'
try {
    $sensor_res = Invoke-CtdRequest -Path '/ranger/system/check' -Query @{ site_id = '1' }
    $sensor_data = Get-Json $sensor_res
    $assessment_status = if (Test-Truthy (Get-Prop $sensor_data 'success')) { 'INFO' } else { 'FAIL' }

    $sensor_table = @(('=' * 80), "$(PadR 'SENSOR NAME' 40) | $(PadR 'IP ADDRESS' 15) | CONNECTED", ('-' * 80))
    $parents = Get-Prop (Get-Prop (Get-Prop $sensor_data 'data') 'statuses') 'parents' @()

    if (Test-Truthy $parents) {
        foreach ($p in $parents) {
            $sensor_table += "$(PadR (Get-Prop $p 'name' 'Unknown') 40) | $(PadR (Get-Prop $p 'address' 'N/A') 15) | $(ConvertTo-PyStr (Get-Prop $p 'is_connected' $false))"
        }
    } else {
        $sensor_table += "$(PadR 'No sensors connected' 40) | $(PadR 'N/A' 15) | N/A"
    }
    $sensor_table += ('=' * 80)

    $report_metrics['Collection Methods / Sensors'] = @{ status = $assessment_status; raw = ($sensor_table -join "`n") }
} catch {
    $report_metrics['Collection Methods / Sensors'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# 11. AUDIT: Interface List
# =============================================================================
Write-Host '[*] Fetching Metric: Network Interfaces...'
try {
    $remote_name = $null

    $loc_res = Invoke-CtdRequest -Path '/ranger/wizard/remote_locations' -Query @{ site_id = '1' }
    if ($loc_res.StatusCode -eq 200) {
        $loc_data = Get-Json $loc_res
        if ($loc_data -is [System.Collections.IList] -and $loc_data.Count -gt 0) {
            $remote_name = Get-Prop $loc_data[0] 'id'
        } elseif ((Test-HasProp $loc_data 'objects') -and (Get-Count (Get-Prop $loc_data 'objects')) -gt 0) {
            $remote_name = Get-Prop (Get-Prop $loc_data 'objects')[0] 'id'
        }
    }

    if (-not (Test-Truthy $remote_name)) {
        $lic_res = Invoke-CtdRequest -Path '/ranger/license' -Query @{ site_id = '1' }
        if ($lic_res.StatusCode -eq 200) {
            $lic_data = Get-Json $lic_res
            $remote_name = Get-Prop (Get-Prop $lic_data 'data') 'machine_uuid'
        }
    }

    if (-not (Test-Truthy $remote_name)) {
        $remote_name = '072043d5-2ad1-5937-e26a-c5d0ec0b09ff'
    }

    $iface_res = Invoke-CtdRequest -Path '/ranger/wizard/interfaces' -Query ([ordered]@{ remote_name = (ConvertTo-PyStr $remote_name); site_id = '1' })
    $iface_data = Get-Json $iface_res

    $iface_list = if (Test-IsDict $iface_data) { Get-Prop $iface_data 'data' @() } else { @() }

    # WIZARD CHECK: No DPI interfaces detected
    if ($DEFAULT_CONFIG.require_span_interface) {
        $has_ingestion = $false
        foreach ($iface in $iface_list) {
            if (((Get-Prop $iface 'is_management') -eq $false) -and ((Get-Prop $iface 'enabled') -eq $true)) { $has_ingestion = $true; break }
        }
        if (-not $has_ingestion) {
            $actionable_insights.Add('Interfaces: No DPI interfaces detected; Continuous monitoring and threat detection is not possible.')
        }
    }

    $iface_table = @(('=' * 95), "$(PadR 'INTERFACE' 25) | $(PadR 'IP ADDRESS' 15) | $(PadR 'MAC ADDRESS' 20) | $(PadR 'PROCESS DATA' 12) | MANAGEMENT", ('-' * 95))
    if (Test-Truthy $iface_list) {
        foreach ($iface in $iface_list) {
            $raw_name = ConvertTo-PyStr (Get-Prop $iface 'name' 'N/A')
            $is_mgmt_bool = Test-Truthy (Get-Prop $iface 'is_management')
            $if_name = if ($is_mgmt_bool) { "Management ($raw_name)" } else { $raw_name }
            $proc_data = if (Test-Truthy (Get-Prop $iface 'enabled')) { 'Enabled' } else { 'Disabled' }
            $is_mgmt = if ($is_mgmt_bool) { 'True' } else { 'False' }
            $iface_table += "$(PadR $if_name 25) | $(PadR (Get-Prop $iface 'ip' 'N/A') 15) | $(PadR (Get-Prop $iface 'mac' 'N/A') 20) | $(PadR $proc_data 12) | $is_mgmt"
        }
    } else {
        $iface_table += 'No network interfaces found.'
    }
    $iface_table += ('=' * 95)

    $report_metrics['Interface List'] = @{ status = 'INFO'; raw = ($iface_table -join "`n") }
} catch {
    $report_metrics['Interface List'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# 12. AUDIT: Network List (With Known Threat Detection)
# =============================================================================
Write-Host '[*] Fetching Metric: Advanced Network Settings Table...'
try {
    $net_params = [ordered]@{ sort = 'name'; page = '1'; per_page = '100' }
    $net_res = Invoke-CtdRequest -Path '/ranger/networks' -Query $net_params
    $net_data = Get-Json $net_res
    $net_objects = Get-Prop $net_data 'objects'

    if ((Test-HasProp $net_data 'objects') -and (Test-Truthy $net_objects)) {
        $net_lines = @(('=' * 105), "$(PadR '#' 3) | $(PadR 'NETWORK / ENVIRONMENT NAME' 30) | $(PadR 'ID' 5) | $(PadR 'KNOWN THREAT DETECTION' 22) | STORE RAW DATA (PCAP)", ('-' * 105))
        $count = 0
        foreach ($item in $net_objects) {
            $count++
            $network_name = Get-FirstTruthy (Get-Prop $item 'name') 'Unknown Network'
            $network_id = Get-FirstTruthy (Get-Prop $item 'id') 'N/A'
            $known_threats_bool = Get-Prop $item 'use_known_threats' $true
            $save_caps_bool = Get-Prop $item 'save_caps' $false

            $known_threats = if (Test-Truthy $known_threats_bool) { 'Enabled' } else { 'Disabled' }
            $save_caps = if (Test-Truthy $save_caps_bool) { 'Enabled' } else { 'Disabled' }

            if (-not (Test-Truthy $known_threats_bool)) {
                $actionable_insights.Add("Networks: KNOWN THREAT DETECTION is disabled on network profile '$(ConvertTo-PyStr $network_name)'.")
            }

            $net_lines += "$(PadR $count 3) | $(PadR $network_name 30) | $(PadR $network_id 5) | $(PadR $known_threats 22) | $save_caps"
        }
        $net_lines += ('=' * 105)
        $report_metrics['Network List'] = @{ status = 'PASS'; raw = ($net_lines -join "`n") }
    } else {
        $report_metrics['Network List'] = @{ status = 'REVIEW'; raw = 'No configured network profiles discovered.' }
    }
} catch {
    $report_metrics['Network List'] = @{ status = 'ERROR'; raw = "Error formatting network table: $($_.Exception.Message)" }
}

# =============================================================================
# 13. AUDIT: Deep Packet Inspection (DPI) Protocols Tables & Drift Engine
# =============================================================================
Write-Host '[*] Fetching Metric: DPI Protocols Configurations...'
try {
    $proto_res = Invoke-CtdRequest -Path '/ranger/ranger_api/protocols' -Query @{ site_id = '1' }
    $proto_data = Get-Json $proto_res

    $assessment_status = 'PASS'

    if (Test-Truthy (Get-Prop $proto_data 'success')) {
        $drifted_protocols = New-Object System.Collections.Generic.List[string]
        $proto_master_list = New-Object System.Collections.Generic.List[object]

        foreach ($proto in (Get-Prop $proto_data 'data' @())) {
            $proto_name = ConvertTo-PyStr (Get-Prop $proto 'name' 'Unknown')
            $is_en = Get-Prop $proto 'is_enabled'

            $proto_master_list.Add([pscustomobject]@{ Name = $proto_name; Enabled = $is_en })

            if ($DEFAULT_PROTOCOLS.ContainsKey($proto_name)) {
                $default_en = $DEFAULT_PROTOCOLS[$proto_name]
                if ($is_en -ne $default_en) {
                    $drifted_protocols.Add("'$proto_name' (Live: $(ConvertTo-PyStr $is_en), Default: $(ConvertTo-PyStr $default_en))")
                }
            }
        }

        # Sort by lower-cased name using ordinal (code point) order, like Python's sort
        $proto_master_list.Sort([System.Comparison[object]] {
            param($x, $y)
            [string]::CompareOrdinal($x.Name.ToLowerInvariant(), $y.Name.ToLowerInvariant())
        })

        $combined_table = @(
            'Legend: + = Enabled/Turned On | x = Disabled/Turned Off',
            ('=' * 55),
            (Format-Center 'DPI PROTOCOLS' 55),
            ('-' * 55)
        )
        foreach ($entry in $proto_master_list) {
            if (Test-Truthy $entry.Enabled) { $combined_table += " + $($entry.Name)" }
            else                            { $combined_table += " x $($entry.Name)" }
        }
        $combined_table += ('=' * 55)

        if ($drifted_protocols.Count -gt 0) {
            $assessment_status = 'REVIEW'
            $actionable_insights.Add("Protocols: The following protocols deviate from the default configuration: $($drifted_protocols -join ', ').")
        }

        $report_metrics['DPI Protocols State'] = @{ status = $assessment_status; raw = ($combined_table -join "`n") }
    }
} catch {
    $report_metrics['DPI Protocols State'] = @{ status = 'ERROR'; raw = "Error: $($_.Exception.Message)" }
}

# =============================================================================
# POST-INSTALL CHECKLIST POPULATION
# =============================================================================
function Test-AnyInsightContains([string]$needle) {
    foreach ($x in $script:actionable_insights) { if ($x.Contains($needle)) { return $true } }
    return $false
}

function Get-MetricStatus([string]$metric) {
    if ($script:report_metrics.Contains($metric)) { return $script:report_metrics[$metric].status }
    return 'UNKNOWN'
}

$checklist = @(
    @("Verify 'Known Threat Alert Detection' enabled", $(if (Test-AnyInsightContains 'KNOWN THREAT DETECTION is disabled') { 'REVIEW' } else { 'PASS' })),
    @("Passive Collection: Verify 'Process Data' Enabled on collection interface(s)", $(if (Test-AnyInsightContains 'No DPI interfaces detected') { 'REVIEW' } else { 'PASS' })),
    @('Passive Collection: Verify traffic counters on collection interface(s)', 'MANUAL'),
    @('Verify Server Health Status (CPU, memory, storage, application health) within limits', (Get-MetricStatus 'System Health Summary')),
    @('Verify proper system mode for desired test cases (Training vs. Operational)', "INFO ($extracted_system_mode)"),
    @('Edge: Demo/production license required to support Edge client uploads', (Get-MetricStatus 'License Status')),
    @('Review required protocols on Interface Management', (Get-MetricStatus 'DPI Protocols State'))
)

# =============================================================================
# TXT OUTPUT GENERATOR (3 SECTIONS)
# =============================================================================
Write-Host "`n[*] Generating Comprehensive TXT Baseline Report..."
$txt_filename = "ctd_best_practice_report_$timestamp.txt"

$sb = New-Object System.Text.StringBuilder
function W([string]$s) { [void]$script:sb.Append($s) }

W (('=' * 70) + "`n")
W "                CLAROTY CTD BEST PRACTICE WIZARD REPORT`n"
W (('=' * 70) + "`n")
W "Script Version   : $SCRIPT_VERSION`n"
W "Audit Run Date   : $current_date`n"
W "Audit Run Time   : $current_time`n`n"

# SECTION 1: SUMMARY
W "--- 1) SUMMARY ---`n"
W "Target Appliance : $ctd_ip`n"
W "Base Version     : $extracted_base_version`n"
W "Update Version   : $extracted_update_version`n"
W "Threat Bundle    : $extracted_threat_bundle`n"
W "System Mode      : $extracted_system_mode`n"
W "FIPS Mode        : $extracted_fips_mode`n"
W "Zone Grouping    : $extracted_zone_grouping`n"
W "Alert Sensitivity: $extracted_alert_sensitivity`n"
W "Assets           : $extracted_assets_summary`n`n"

W "ESSENTIAL POST-INSTALL TASKS - VERIFICATION CHECKLIST:`n"
foreach ($c in $checklist) {
    W "  [$(Format-Center ([string]$c[1]) 6)] $($c[0])`n"
}
W ("`n" + ('=' * 70) + "`n`n")

# SECTION 2: RECOMMENDATIONS
W "--- 2) RECOMMENDATIONS ---`n"
if ($actionable_insights.Count -gt 0) {
    W "The following deviations from a default installation were observed:`n`n"
    foreach ($insight in $actionable_insights) {
        W "  * $insight`n"
    }
} else {
    W "System perfectly matches the Federal Golden Baseline configuration. No deviations detected.`n"
}
W ("`n" + ('=' * 70) + "`n`n")

# SECTION 3: DATA
W "--- 3) DATA ---`n`n"
foreach ($metric_name in $report_metrics.Keys) {
    $details = $report_metrics[$metric_name]
    W "### $metric_name ###`n"
    W "STATUS : $($details.status)`n`n"
    W ([string]$details.raw)
    W ("`n`n" + ('-' * 70) + "`n`n")
}

W "`n"
W (('=' * 70) + "`n")
W "End of report`n"
W (('=' * 70) + "`n")

# Python text mode writes the platform newline (CRLF on Windows); UTF-8 without BOM
$report_text = $sb.ToString().Replace("`n", [Environment]::NewLine)
$report_path = Join-Path (Get-Location).ProviderPath $txt_filename
[System.IO.File]::WriteAllText($report_path, $report_text, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ('=' * 70)
Write-Host "$([char]0x2705) Best Practice Wizard execution sequence complete."
Write-Host "$([char]::ConvertFromUtf32(0x1F4E6)) Text Report generated successfully: $txt_filename"
Write-Host ('=' * 70)
#
########################################################################
# End of Script
########################################################################

