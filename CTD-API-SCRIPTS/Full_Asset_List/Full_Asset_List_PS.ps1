<#
=============================================================================
 Script Metadata
-----------------------------------------------------------------------------
 Description:
 This script connects to a Claroty CTD server, authenticates, and retrieves
 a comprehensive list of all assets. It extracts specific fields (chosen 
 dynamically by the user) and saves them to either a CSV or JSON file based 
 on user preference.
=============================================================================
#>

# Bypass SSL Certificate validation (Equivalent to urllib3.disable_warnings & verify=False)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Get-Authentication {
    param (
        [string]$CtdIp,
        [string]$Username,
        [string]$Password
    )
    
    Write-Host "`nAuthenticating to CTD at https://$CtdIp..."
    
    $AuthPayload = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    $Headers = @{
        'Content-type' = 'application/json'
        'Accept'       = 'text/plain'
    }

    try {
        $Response = Invoke-RestMethod -Uri "https://$CtdIp/auth/authenticate" -Method Post -Headers $Headers -Body $AuthPayload -ErrorAction Stop
    }
    catch {
        Write-Host "Connection Error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    if ($Response.error) {
        Write-Host "Authentication Failed: $($Response.error)" -ForegroundColor Red
        exit 1
    }

    Write-Host "Successful Login.`n" -ForegroundColor Green
    
    return @{
        'Authorization' = $Response.token
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

function Get-FieldsInput {
    Write-Host "`n--- Field Selection ---"
    $MandatoryFields = @('id', 'name')
    
    $OptionalFields = @(
        'ipv4', 'ipv6', 'mac', 'os', 'model', 'vendor', 'firmware', 
        'site_id', 'resource_id', 'timestamp', 'last_updated', 'approved', 
        'valid', 'ghost', 'parsed', 'special_hint', 'risk_level', 
        'last_entity_seen', 'site_name', 'network_id', 'subnet_id', 
        'virtual_zone_id', 'virtual_zone_name', 'active_queries_names', 
        'active_tasks_names', 'purdue_level', 'first_seen', 'vlan', 'fdl', 
        'address', 'gateway', 'asset_type', 'class_type', 'hostname', 
        'plc_slots', 'project_parsed', 'serial_number', 'criticality', 
        'domain_workgroup', 'default_gateway', 'edge_last_run', 'edge_id', 
        'installed_antivirus', 'has_interfaces', 'old_ips', 'state', 
        'custom_informations', 'patch_count', 'code_sections', 
        'installed_programs_count', 'usb_devices_count', 'os_build', 
        'os_architecture', 'os_service_pack', 'asset_insight', 'display_name', 
        'protocol', 'last_seen', 'num_alerts', 'children', 'network', 'subnet', 
        'subnet_tag', 'subnet_type', 'custom_attributes', 'insight_names', 'risk_score'
    )

    Write-Host "Mandatory fields (Always included): id, name"
    Write-Host "Optional fields to include:"
    
    for ($i = 0; $i -lt $OptionalFields.Count; $i++) {
        $Index = $i + 1
        Write-Host ("  {0,2}. {1}" -f $Index, $OptionalFields[$i])
    }

    $Selections = (Read-Host "`nEnter numbers or ranges (e.g., 1, 4-8, 12) to include (or press Enter to just pull mandatory fields)").Trim()
        
    $SelectedFields = [System.Collections.Generic.List[string]]::new()
    $SelectedFields.AddRange([string[]]$MandatoryFields)

    if (![string]::IsNullOrEmpty($Selections)) {
        try {
            # Use a HashSet to ensure all indices are unique (preventing duplicates from overlapping ranges)
            $Indices = [System.Collections.Generic.HashSet[int]]::new()
            
            # Split by commas first
            $Parts = $Selections -split ','
            
            foreach ($Part in $Parts) {
                $Part = $Part.Trim()
                if ([string]::IsNullOrEmpty($Part)) { continue }

                # Check if the part is a range
                if ($Part -match '-') {
                    $RangeParts = $Part -split '-', 2
                    $Start = [int]$RangeParts[0].Trim()
                    $End = [int]$RangeParts[1].Trim()

                    # Handle forward and backward inputs gracefully using the range operator (..)
                    if ($Start -le $End) {
                        $Start..$End | ForEach-Object { [void]$Indices.Add($_) }
                    } else {
                        $End..$Start | ForEach-Object { [void]$Indices.Add($_) }
                    }
                }
                # Check if it's a single digit
                elseif ($Part -match '^\d+$') {
                    [void]$Indices.Add([int]$Part)
                }
            }

            # Sort the collected indices so they appear in the original list order
            $SortedIndices = $Indices | Sort-Object

            foreach ($Index in $SortedIndices) {
                if ($Index -ge 1 -and $Index -le $OptionalFields.Count) {
                    $FieldName = $OptionalFields[$Index - 1]
                    if ($SelectedFields -notcontains $FieldName) {
                        $SelectedFields.Add($FieldName)
                    }
                }
            }
        }
        catch {
            Write-Host "Error parsing field selection. Defaulting to mandatory fields only." -ForegroundColor Yellow
        }
    }

    return $SelectedFields
}

function Get-AllAssets {
    param (
        [string]$CtdIp,
        [hashtable]$Headers,
        [array]$Fieldnames
    )
    
    Write-Host "`nFetching Assets..."
    $ParsedAssets = @()
    $Page = 1

    $FieldsParam = $Fieldnames -join ",;$"
    
    # BodyData removed here, as GET requests in PowerShell cannot contain a body.

    while ($true) {
        Write-Host " - Processing page $Page..."
        
        $QueryParams = "?page=$Page&per_page=500&ghost__exact=false&valid__exact=true&special_hint__exact=0&site_id__exact=1&fields=$([uri]::EscapeDataString($FieldsParam))"
        $Uri = "https://$CtdIp/ranger/assets$QueryParams"

        # -Body parameter removed from the Invoke-RestMethod call
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop

        if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
            $AssetList = $Response.objects
            
            foreach ($Asset in $AssetList) {
                $RowData = [ordered]@{}
                
                foreach ($Field in $Fieldnames) {
                    $Value = $Asset.$Field
                    
                    if ($null -eq $Value) {
                        $RowData[$Field] = "None"
                    }
                    elseif ($Value -is [array]) {
                        if ($Value.Count -eq 0) {
                            $RowData[$Field] = "None"
                        } else {
                            $RowData[$Field] = $Value -join ", "
                        }
                    }
                    else {
                        $StringValue = [string]$Value
                        if ([string]::IsNullOrWhiteSpace($StringValue)) {
                            $RowData[$Field] = "None"
                        } else {
                            $RowData[$Field] = $StringValue.Trim()
                        }
                    }
                }
                $ParsedAssets += [PSCustomObject]$RowData
            }
            $Page++
        }
        else {
            Write-Host "Asset extraction complete.`n"
            break
        }
    }
    
    return $ParsedAssets
}


function Export-ToCsv {
    param (
        [string]$Timestamp,
        [array]$ParsedAssets
    )
    $Filename = "total_assets_$Timestamp.csv"
    $ParsedAssets | Export-Csv -Path $Filename -NoTypeInformation -Encoding UTF8
    Write-Host "Data written to file: $Filename" -ForegroundColor Green
}

function Export-ToJson {
    param (
        [string]$Timestamp,
        [array]$ParsedAssets,
        [array]$Fieldnames
    )
    $Filename = "total_assets_$Timestamp.json"
    $OutputData = @()
    
    foreach ($Asset in $ParsedAssets) {
        $FormattedObject = [ordered]@{}
        
        foreach ($Field in $Fieldnames) {
            $Key = if ($Field -eq 'id') { 'asset id' } else { $Field }
            $FormattedObject[$Key] = $Asset.$Field
        }
        $OutputData += [PSCustomObject]$FormattedObject
    }
    
    $OutputData | ConvertTo-Json -Depth 10 | Set-Content -Path $Filename -Encoding UTF8
    Write-Host "Data written to file: $Filename" -ForegroundColor Green
}

# =============================================================================
# Main Execution Block
# =============================================================================
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

Write-Host "=== Claroty CTD Asset Extractor ==="

# Setup & Authentication
$CtdIp = (Read-Host "Enter CTD IP or hostname").Trim()
$Username = (Read-Host "Enter CTD username").Trim()

# Handle password securely, then translate back to plain text for JSON serialization
$SecurePassword = Read-Host "Enter CTD password" -AsSecureString
$Password = [System.Net.NetworkCredential]::new("", $SecurePassword).Password

$Headers = Get-Authentication -CtdIp $CtdIp -Username $Username -Password $Password

# Output preferences & Field selection
$OutputFormat = Get-OutputPreference
$AssetFieldnames = Get-FieldsInput

# Fetch Data
$ParsedAssets = Get-AllAssets -CtdIp $CtdIp -Headers $Headers -Fieldnames $AssetFieldnames
$TotalAssets = $ParsedAssets.Count

# Route Output
if ($TotalAssets -gt 0) {
    if ($OutputFormat -eq 'csv') {
        Export-ToCsv -Timestamp $Timestamp -ParsedAssets $ParsedAssets
    }
    elseif ($OutputFormat -eq 'json') {
        Export-ToJson -Timestamp $Timestamp -ParsedAssets $ParsedAssets -Fieldnames $AssetFieldnames
    }
}
else {
    Write-Host "No valid assets found to export." -ForegroundColor Yellow
}

# Final Summary
Write-Host ("-" * 35)
Write-Host "Summary of Asset Processing"
Write-Host ("-" * 35)
Write-Host ("Total valid assets saved : {0:N0}" -f $TotalAssets)
Write-Host ("-" * 35)
Write-Host "Script execution complete."