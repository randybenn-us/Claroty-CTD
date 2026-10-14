<#
=============================================================================
 Script Metadata
-----------------------------------------------------------------------------
 Description:
 This script connects to a Claroty CTD server, authenticates, and retrieves
 a list of detected Edge hosts. It allows you to pull the installed 3rd-party 
 programs for a single specific host or all detected hosts at once. It 
 cross-references these programs with Claroty's native tracking capabilities 
 (cve_program_matcher_cut.csv) and exports the results to CSV or JSON.
=============================================================================
#>

# Bypass SSL Certificate validation
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# =============================================================================
# Authentication & Setup
# =============================================================================
function Get-Authentication {
    param (
        [string]$CtdIp,
        [string]$Username,
        [SecureString]$Password
    )
    
    Write-Host "`nAuthenticating to CTD at https://$CtdIp..."
    
    $PlainPassword = [System.Net.NetworkCredential]::new("", $Password).Password
    
    $AuthPayload = @{
        username = $Username
        password = $PlainPassword
    } | ConvertTo-Json

    $Headers = @{
        'Content-type' = 'application/json'
        'Accept'       = 'text/plain'
    }

    try {
        $Response = Invoke-RestMethod -Uri "https://$CtdIp/auth/authenticate" -Method Post -Headers $Headers -Body $AuthPayload -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to connect to the server: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    if ($Response.error) {
        Write-Host "Authentication Failed: $($Response.error)" -ForegroundColor Red
        exit 1
    }

    $Token = $Response.token
    if ([string]::IsNullOrEmpty($Token)) {
        Write-Host "Authentication Failed: No token returned by the server." -ForegroundColor Red
        exit 1
    }

    Write-Host "Successful Login.`n" -ForegroundColor Green
    return @{
        'Authorization' = $Token
        'Content-Type'  = 'application/json'
    }
}

function Get-OutputPreference {
    do {
        $Choice = (Read-Host "Would you like the output in CSV or JSON format? (Enter 'csv' or 'json')").Trim().ToLower()
        if ($Choice -in @('csv', 'json')) {
            return $Choice
        }
        Write-Host "Invalid input. Please type 'csv' or 'json'." -ForegroundColor Yellow
    } while ($true)
}

# =============================================================================
# Asset & Program Querying
# =============================================================================
function Get-EdgeAssets {
    param (
        [string]$CtdIp,
        [hashtable]$Headers
    )
    Write-Host "Querying assets for active edge_ids..."
    
    $RawAssets = [System.Collections.Generic.List[psobject]]::new()
    $AssetPage = 1
    $AssetPerPage = 500
    
    while ($true) {
        $QueryString = "?page=$AssetPage&per_page=$AssetPerPage&fields=$([uri]::EscapeDataString('id,;$name,;$edge_id,;$subnet,;$os'))"
        $AssetUrl = "https://$CtdIp/ranger/assets$QueryString"
        
        try {
            $Response = Invoke-RestMethod -Uri $AssetUrl -Method Get -Headers $Headers -ErrorAction Stop
            
            if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
                # Add items safely to avoid PowerShell array-casting bug
                foreach ($Item in $Response.objects) {
                    $RawAssets.Add($Item)
                }
                
                if ($Response.objects.Count -lt $AssetPerPage) { break }
                $AssetPage++
            }
            else {
                break
            }
        }
        catch {
            Write-Host "Failed to fetch assets on page $AssetPage`: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
            
    # Filter out null edge_ids and normalize properties (handling Claroty's ';$name' format)
    $EdgeAssets = @()
    foreach ($A in $RawAssets) {
        $EdgeId = if ($A.edge_id) { $A.edge_id } else { $A.';$edge_id' }
        
        if (![string]::IsNullOrWhiteSpace($EdgeId)) {
            $Id = $A.id
            $ResourceId = if ($A.resource_id) { $A.resource_id } else { "$Id-1" }
            $Name = if ($A.name) { $A.name } elseif ($A.';$name') { $A.';$name' } else { "Unknown" }
            $Os = if ($A.os) { $A.os } elseif ($A.';$os') { $A.';$os' } else { "Unknown" }
            $Subnet = if ($A.subnet) { $A.subnet } elseif ($A.';$subnet') { $A.';$subnet' } else { "Unknown" }

            $EdgeAssets += @{
                id          = $Id
                resource_id = $ResourceId
                name        = $Name
                edge_id     = $EdgeId
                os          = $Os
                subnet      = $Subnet
            }
        }
    }
    
    return $EdgeAssets
}

function Get-EdgeHostSelection {
    param ([array]$EdgeAssets)
    
    if (-not $EdgeAssets -or $EdgeAssets.Count -eq 0) {
        Write-Host "No Edge assets found in this environment. Exiting." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "`n--- Detected Edge Assets ($($EdgeAssets.Count) Found) ---"
    Write-Host ("{0,-10} | {1,-30} | {2,-38} | {3}" -f "Asset ID", "Asset Name", "Edge ID", "OS")
    Write-Host ("-" * 105)
    
    foreach ($Asset in $EdgeAssets) {
        Write-Host ("{0,-10} | {1,-30} | {2,-38} | {3}" -f $Asset.id, $Asset.name, $Asset.edge_id, $Asset.os)
    }
    Write-Host ("-" * 105)

    $TargetId = (Read-Host "`nEnter an Asset ID to pull programs for a specific Edge host (or press Enter for ALL hosts)").Trim()

    if ([string]::IsNullOrEmpty($TargetId)) {
        Write-Host "Processing ALL Edge hosts.`n"
        return $EdgeAssets
    }

    # Filter for the chosen host
    $Selected = $EdgeAssets | Where-Object { [string]$_.id -eq $TargetId }
    
    if (-not $Selected -or $Selected.Count -eq 0) {
        Write-Host "Asset ID '$TargetId' not found in detected Edge assets. Proceeding with ALL Edge hosts.`n" -ForegroundColor Yellow
        return $EdgeAssets
    }

    Write-Host ("Filtering for selected Edge host: ID {0} ({1})`n" -f $Selected[0].id, $Selected[0].name)
    return $Selected
}

function Get-InstalledPrograms {
    param (
        [string]$CtdIp,
        [hashtable]$Headers,
        [hashtable]$Asset
    )
    
    $AssetId = $Asset.id
    $ResourceId = $Asset.resource_id
    
    Write-Host "Fetching installed programs for Asset ID $AssetId ($($Asset.name))..."
    $AllPrograms = [System.Collections.Generic.List[psobject]]::new()
    $Page = 1
    $PerPage = 500
    
    while ($true) {
        $QueryString = "?fields=$([uri]::EscapeDataString('name,;$version,;$vendor'))&sort=name&page=$Page&per_page=$PerPage&asset_rid__exact=$ResourceId"
        $Url = "https://$CtdIp/ranger/ranger_api/asset_installed_programs$QueryString"
        
        try {
            $Response = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers -ErrorAction Stop
            
            if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
                foreach ($Item in $Response.objects) {
                    $AllPrograms.Add($Item)
                }
                
                if ($Response.objects.Count -lt $PerPage) { break }
                $Page++
            }
            else {
                break
            }
        }
        catch {
            Write-Host "Error pulling programs on page $Page for Asset $AssetId`: $($_.Exception.Message)" -ForegroundColor Red
            break
        }
    }
            
    return $AllPrograms.ToArray()
}

# =============================================================================
# Native CVE Matcher Logic
# =============================================================================
function Get-CveMatcherMap {
    param ([string]$CsvFilepath)
    
    $MatcherMap = @{}
    
    if (Test-Path $CsvFilepath) {
        try {
            # Read all lines manually to ensure we bypass missing header errors
            $Lines = Get-Content $CsvFilepath
            $ProgramCount = 0
            
            # Start at index 1 to skip the header
            for ($i = 1; $i -lt $Lines.Count; $i++) {
                $Row = $Lines[$i] -split ','
                if ($Row.Count -ge 2) {
                    $Vendor = $Row[0].Trim().ToLower()
                    $Program = $Row[1].Trim().ToLower()
                    
                    if (![string]::IsNullOrEmpty($Vendor) -and ![string]::IsNullOrEmpty($Program)) {
                        if (-not $MatcherMap.ContainsKey($Vendor)) {
                            $MatcherMap[$Vendor] = [System.Collections.Generic.List[string]]::new()
                        }
                        $MatcherMap[$Vendor].Add($Program)
                        $ProgramCount++
                    }
                }
            }
            Write-Host "Loaded $ProgramCount reference programs across $($MatcherMap.Count) vendors from $CsvFilepath.`n"
        }
        catch {
            Write-Host "Error parsing $CsvFilepath. 'in_CTD' tracking will default to 'no'.`n" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "WARNING: $CsvFilepath not found. 'in_CTD' tracking will default to 'no'.`n" -ForegroundColor Yellow
    }
    
    return $MatcherMap
}

function Test-InCtd {
    param (
        [string]$ApiVendor,
        [string]$ApiProgram,
        $MatcherMap
    )
    
    if (-not $MatcherMap -or $MatcherMap.Count -eq 0) { return "no" }
        
    $ApiVendorNorm = $ApiVendor.Trim().ToLower()
    $ApiProgNorm = $ApiProgram.Trim().ToLower()

    if ($MatcherMap.ContainsKey($ApiVendorNorm)) {
        foreach ($CsvProgram in $MatcherMap[$ApiVendorNorm]) {
            # Python 'in' equivalent: does the API program contain the CSV substring?
            if ($ApiProgNorm.Contains($CsvProgram)) {
                return "yes"
            }
        }
    }
            
    return "no"
}

# =============================================================================
# Exporting
# =============================================================================
function Export-Programs {
    param (
        [string]$Timestamp,
        [hashtable]$Asset,
        [array]$ProgramsList,
        $MatcherMap,
        [string]$OutputFormat
    )
    
    $AssetId = $Asset.id
    $AssetName = $Asset.name
    
    if ($OutputFormat -eq 'csv') {
        $Filename = "${AssetId}_programs_list_${Timestamp}.csv"
        try {
            $CsvData = [System.Collections.Generic.List[psobject]]::new()
            
            foreach ($Obj in $ProgramsList) {
                $Program = if ($Obj.name) { $Obj.name } else { "" }
                $Vendor  = if ($Obj.';$vendor') { $Obj.';$vendor' } elseif ($Obj.vendor) { $Obj.vendor } else { "" }
                $Version = if ($Obj.';$version') { $Obj.';$version' } elseif ($Obj.version) { $Obj.version } else { "" }
                $InCtd   = Test-InCtd -ApiVendor $Vendor -ApiProgram $Program -MatcherMap $MatcherMap
                
                $CsvData.Add([PSCustomObject]@{
                    'program' = $Program
                    'vendor'  = $Vendor
                    'version' = $Version
                    'in_CTD'  = $InCtd
                })
            }
            
            $CsvData | Export-Csv -Path $Filename -NoTypeInformation -Encoding UTF8
            Write-Host "Successfully exported CSV for Asset ID $AssetId ($AssetName) -> $Filename" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to write CSV for Asset $AssetId`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    elseif ($OutputFormat -eq 'json') {
        $Filename = "${AssetId}_programs_list_${Timestamp}.json"
        
        $JsonPrograms = [System.Collections.Generic.List[psobject]]::new()
        foreach ($Obj in $ProgramsList) {
            $Program = if ($Obj.name) { $Obj.name } else { "" }
            $Vendor  = if ($Obj.';$vendor') { $Obj.';$vendor' } elseif ($Obj.vendor) { $Obj.vendor } else { "" }
            $Version = if ($Obj.';$version') { $Obj.';$version' } elseif ($Obj.version) { $Obj.version } else { "" }
            $InCtd   = Test-InCtd -ApiVendor $Vendor -ApiProgram $Program -MatcherMap $MatcherMap
            
            $JsonPrograms.Add([PSCustomObject]@{
                "program" = $Program
                "vendor"  = $Vendor
                "version" = $Version
                "in_CTD"  = $InCtd
            })
        }
        
        $JsonOutput = [PSCustomObject]@{
            "asset_id"      = $AssetId
            "asset_name"    = $AssetName
            "edge_id"       = $Asset.edge_id
            "program_count" = $ProgramsList.Count
            "programs"      = $JsonPrograms.ToArray()
        }
        
        try {
            # 1. Generate Raw JSON
            $RawJson = $JsonOutput | ConvertTo-Json -Depth 10
            
            # 2. Fix PS5.1 formatting spacing bugs
            $RawJson = $RawJson -replace '":\s+', '": '
            
            $Indent = 0
            $CleanJson = @()
            foreach ($Line in ($RawJson -split "`r`n|`n")) {
                $Trimmed = $Line.Trim()
                if ($Trimmed -match '^[\]\}]') { $Indent -= 4 }
                $CleanJson += (" " * [Math]::Max(0, $Indent)) + $Trimmed
                if ($Trimmed -match '[\{\[]$') { $Indent += 4 }
            }
            
            $FinalJson = $CleanJson -join "`r`n"
            $FinalJson | Set-Content -Path $Filename -Encoding UTF8
            
            Write-Host "Successfully exported JSON for Asset ID $AssetId ($AssetName) -> $Filename" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to write JSON for Asset $AssetId`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# =============================================================================
# Main Execution Block
# =============================================================================
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

Write-Host "=== Claroty CTD Edge Asset Programs Extractor ==="

# 1. Credentials
$CtdIp = (Read-Host "Enter CTD IP or hostname").Trim()
$Username = (Read-Host "Enter CTD username").Trim()
$SecurePassword = Read-Host "Enter CTD password" -AsSecureString

# 2. Setup & Matcher Map
$Headers = Get-Authentication -CtdIp $CtdIp -Username $Username -Password $SecurePassword

$MatcherCsv = "cve_program_matcher_cut.csv"
$MatcherMap = Get-CveMatcherMap -CsvFilepath $MatcherCsv

# 3. Query Edge Hosts & Prompt Selection
$AllEdgeAssets = Get-EdgeAssets -CtdIp $CtdIp -Headers $Headers
$TargetAssets = Get-EdgeHostSelection -EdgeAssets $AllEdgeAssets
$OutputFormat = Get-OutputPreference

# 4. Process Each Selected Host
Write-Host "`nStarting program extraction..."
foreach ($Asset in $TargetAssets) {
    $ProgramsList = Get-InstalledPrograms -CtdIp $CtdIp -Headers $Headers -Asset $Asset
    Write-Host ("Found {0} 3rd-party programs for Asset ID {1}." -f $ProgramsList.Count, $Asset.id)
    
    if ($ProgramsList -and $ProgramsList.Count -gt 0) {
        Export-Programs -Timestamp $Timestamp -Asset $Asset -ProgramsList $ProgramsList -MatcherMap $MatcherMap -OutputFormat $OutputFormat
    }
    else {
        Write-Host "No installed programs returned for Asset ID $($Asset.id)." -ForegroundColor Yellow
    }
    Write-Host ("-" * 50)
}

Write-Host "Script execution complete."