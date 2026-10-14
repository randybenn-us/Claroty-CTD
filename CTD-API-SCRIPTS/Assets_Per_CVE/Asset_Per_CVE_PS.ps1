<#
=============================================================================
 Script Metadata
-----------------------------------------------------------------------------
 Description:
 This script connects to a Claroty CTD server, authenticates, and retrieves 
 a list of confirmed CVEs along with associated assets. Output is modularized
 and can be exported to either CSV or a nested JSON format based on user input.
 It also includes an optional time filter to only pull recently seen assets.
=============================================================================
#>

# Bypass SSL Certificate validation
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# =============================================================================
# User Input Functions
# =============================================================================
function Get-CveInput {
    Write-Host "`n--- CVE Filter ---"
    $CveId = (Read-Host "Enter a specific CVE ID to filter by (or press Enter to pull all CVEs)").Trim()
    if ([string]::IsNullOrEmpty($CveId)) { return $null }
    return $CveId
}

function Get-TimeFilter {
    Write-Host "`n--- Time Filter ---"
    $StartTimeStr = (Read-Host "Enter a START time window (MM/DD/YYYY) or press Enter for none").Trim()
    $EndTimeStr = (Read-Host "Enter an END time window (MM/DD/YYYY) or press Enter for none").Trim()

    $StartUtc = $null
    $EndUtc = $null

    try {
        if (![string]::IsNullOrEmpty($StartTimeStr)) {
            # Get-Date is more forgiving with missing leading zeroes than ParseExact
            $DtStart = Get-Date $StartTimeStr
            $StartUtc = $DtStart.ToString("yyyy-MM-ddTHH:mm:ss.000Z")
            Write-Host $StartUtc
        }
        if (![string]::IsNullOrEmpty($EndTimeStr)) {
            # Set to the end of the day for the end window
            $DtEnd = (Get-Date $EndTimeStr).Date.AddHours(23).AddMinutes(59).AddSeconds(59)
            $EndUtc = $DtEnd.ToString("yyyy-MM-ddTHH:mm:ss.000Z")
            Write-Host $EndUtc
        }
    }
    catch {
        Write-Host "Invalid date format entered. Proceeding without time filters." -ForegroundColor Yellow
        return @{ Start = $null; End = $null }
    }

    return @{ Start = $StartUtc; End = $EndUtc }
}

function Get-FieldsInput {
    Write-Host "`n--- Field Selection ---"
    $MandatoryFields = @('cve_id', 'asset_id', 'asset_name')
    
    $OptionalFields = @(
        'class_type', 'ipv4', 'ipv6', 'mac', 'vendor', 
        'os', 'model', 'firmware', 'serial_number', 'num_alerts', 'insight_names'
    )

    Write-Host "Mandatory fields (Always included): cve_id, asset_id, asset_name"
    Write-Host "Optional fields to include:"
    
    for ($i = 0; $i -lt $OptionalFields.Count; $i++) {
        $Index = $i + 1
        Write-Host ("  {0}. {1}" -f $Index, $OptionalFields[$i])
    }

    $Selections = (Read-Host "`nEnter a comma-separated list of numbers to include (or press Enter for default)").Trim()
    
    $SelectedFields = [System.Collections.Generic.List[string]]::new()
    $SelectedFields.AddRange([string[]]$MandatoryFields)
    $AdditionalFields = [System.Collections.Generic.List[string]]::new()

    if (![string]::IsNullOrEmpty($Selections)) {
        try {
            $Indices = $Selections -split ',' | Where-Object { $_ -match '^\s*\d+\s*$' } | ForEach-Object { [int]$_.Trim() }
            foreach ($Index in $Indices) {
                if ($Index -ge 1 -and $Index -le $OptionalFields.Count) {
                    $FieldName = $OptionalFields[$Index - 1]
                    if ($SelectedFields -notcontains $FieldName) {
                        $SelectedFields.Add($FieldName)
                        $AdditionalFields.Add($FieldName)
                    }
                }
            }
        }
        catch {
            Write-Host "Error parsing field selection, defaulting to mandatory fields." -ForegroundColor Yellow
        }
    }

    return @{
        FieldsParam = ($SelectedFields -join ",;$")
        AdditionalFields = $AdditionalFields.ToArray()
    }
}

function Get-OutputPreference {
    Write-Host "`n--- Output Format ---"
    do {
        $Choice = (Read-Host "Would you like the output in CSV or JSON format? (Enter 'csv' or 'json')").Trim().ToLower()
        if ($Choice -in @('csv', 'json')) {
            return $Choice
        }
        Write-Host "Invalid input. Please type 'csv' or 'json'." -ForegroundColor Yellow
    } while ($true)
}

# =============================================================================
# Auth/Endpoints
# =============================================================================
function Get-Authentication {
    param (
        [string]$CtdIp,
        [string]$Username,
        [string]$Password
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
        Write-Host "Connection Error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    if ($Response.error) {
        Write-Host "Authentication Failed: $($Response.error)" -ForegroundColor Red
        exit 1
    }

    Write-Host "Successful Login.`n" -ForegroundColor Green
    return $Response.token
}

function Get-AssetVulnerabilities {
    param (
        [string]$CtdIp,
        [string]$AuthToken,
        [string]$TargetCve,
        [string]$StartUtc,
        [string]$EndUtc,
        [string]$FieldsParam
    )
    Write-Host "Fetching asset vulnerabilities..."
    
    $Headers = @{ 'Authorization' = $AuthToken }
    $RawVulnerabilities = [System.Collections.Generic.List[psobject]]::new()
    $Page = 1

    while ($true) {
        # Base query string
        $QueryString = "?page=$Page&per_page=500&site_id__exact=1&ghost__exact=false&special_hint__exact=0&relevance__exact=1&fields=$([uri]::EscapeDataString($FieldsParam))"
        
        # Apply Optional Filters
        if (![string]::IsNullOrEmpty($TargetCve)) {
            $QueryString += "&cve_id__exact=$([uri]::EscapeDataString($TargetCve))"
        }
        if (![string]::IsNullOrEmpty($StartUtc)) {
            $QueryString += "&created_at__gte=$([uri]::EscapeDataString($StartUtc))"
        }
        if (![string]::IsNullOrEmpty($EndUtc)) {
            $QueryString += "&created_at__lte=$([uri]::EscapeDataString($EndUtc))"
        }

        $Uri = "https://$CtdIp/ranger/asset-vulnerabilities$QueryString"

        try {
            $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop
        }
        catch {
            Write-Host "Error fetching data on page $Page`: $($_.Exception.Message)" -ForegroundColor Red
            break
        }

        if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
            foreach ($Item in $Response.objects) {
                $RawVulnerabilities.Add($Item)
            }
            Write-Host ("Fetched page {0} ({1} records)..." -f $Page, $Response.objects.Count)
            $Page++
        }
        else {
            break
        }
    }

    return $RawVulnerabilities.ToArray()
}

# =============================================================================
# Output Generation
# =============================================================================
function Format-Value {
    param ($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [array]) { return ($Value -join ", ") }
    return [string]$Value
}

function Export-ToCsv {
    param (
        [string]$Timestamp,
        $RawData,
        [array]$AdditionalFields
    )
    
    # Replicate Python's defaultdict(list)
    $CveGroups = @{}
    foreach ($Item in $RawData) {
        $CveId = [string]$Item.cve_id
        if (![string]::IsNullOrEmpty($CveId)) {
            if (-not $CveGroups.ContainsKey($CveId)) {
                $CveGroups[$CveId] = [System.Collections.Generic.List[psobject]]::new()
            }
            $CveGroups[$CveId].Add($Item)
        }
    }

    $CveListFilename = "CVE_List_$Timestamp.csv"
    $AssetsPerCveFilename = "Assets_Per_CVEs_$Timestamp.csv"

    $SortedCves = $CveGroups.Keys | Sort-Object

    # 1. Export CVE_List_{timestamp}.csv
    try {
        $Csv1Data = [System.Collections.Generic.List[psobject]]::new()
        foreach ($Cve in $SortedCves) {
            $Csv1Data.Add([PSCustomObject]@{
                'CVE ID'                = $Cve
                'Confirmed Asset Count' = $CveGroups[$Cve].Count
            })
        }
        $Csv1Data | Export-Csv -Path $CveListFilename -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Host "Error writing to $CveListFilename`: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 2. Export Assets_Per_CVEs_{timestamp}.csv
    try {
        $TextInfo = (Get-Culture).TextInfo
        $FormattedAdditionalFields = $AdditionalFields | ForEach-Object { $TextInfo.ToTitleCase($_.Replace('_', ' ')) }
        
        $Csv2Data = [System.Collections.Generic.List[psobject]]::new()
        
        foreach ($Cve in $SortedCves) {
            $ItemIndex = 1
            $Assets = $CveGroups[$Cve]
            
            foreach ($Asset in $Assets) {
                $AssetName = if ($Asset.asset_name) { $Asset.asset_name } else { "Unknown" }
                $AssetId = if ($Asset.asset_id) { $Asset.asset_id } else { "Unknown" }
                
                $Row = [ordered]@{
                    'CVE ID'     = $Cve
                    'Item'       = $ItemIndex
                    'Asset Name' = $AssetName
                    'Asset ID'   = $AssetId
                }
                
                # Append dynamic fields
                for ($i = 0; $i -lt $AdditionalFields.Count; $i++) {
                    $RawField = $AdditionalFields[$i]
                    $HeaderName = $FormattedAdditionalFields[$i]
                    $Row[$HeaderName] = Format-Value -Value $Asset.$RawField
                }
                
                $Csv2Data.Add([PSCustomObject]$Row)
                $ItemIndex++
            }
        }
        $Csv2Data | Export-Csv -Path $AssetsPerCveFilename -NoTypeInformation -Encoding UTF8
        
        Write-Host "`nSuccessfully exported CSV reports:`n - $CveListFilename`n - $AssetsPerCveFilename" -ForegroundColor Green
    }
    catch {
        Write-Host "Error writing to $AssetsPerCveFilename`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-ToJson {
    param (
        [string]$Timestamp,
        $RawData,
        [array]$AdditionalFields
    )
    
    $CveGroups = @{}
    foreach ($Item in $RawData) {
        $CveId = [string]$Item.cve_id
        if (![string]::IsNullOrEmpty($CveId)) {
            if (-not $CveGroups.ContainsKey($CveId)) {
                $CveGroups[$CveId] = [System.Collections.Generic.List[psobject]]::new()
            }
            $CveGroups[$CveId].Add($Item)
        }
    }

    $JsonFilename = "Assets_Per_CVE_$Timestamp.json"
    $OutputData = [System.Collections.Generic.List[psobject]]::new()
    $SortedCves = $CveGroups.Keys | Sort-Object

    foreach ($Cve in $SortedCves) {
        $Assets = $CveGroups[$Cve]
        $AssetMapping = [ordered]@{}
        
        foreach ($Asset in $Assets) {
            $A_Id = if ($Asset.asset_id) { [string]$Asset.asset_id } else { "Unknown" }
            $A_Name = if ($Asset.asset_name) { $Asset.asset_name } else { "Unknown" }
            
            # The list contains the asset name, followed by any additional requested fields
            $AssetDetails = [System.Collections.Generic.List[string]]::new()
            $AssetDetails.Add($A_Name)
            
            foreach ($Field in $AdditionalFields) {
                $AssetDetails.Add((Format-Value -Value $Asset.$Field))
            }
            
            $AssetMapping[$A_Id] = $AssetDetails.ToArray()
        }

        $OutputData.Add([PSCustomObject]@{
            "cve id"      = $Cve
            "asset count" = $Assets.Count
            "asset list"  = $AssetMapping
        })
    }

    try {
        # 1. Generate the raw (ugly) JSON string
        $RawJson = $OutputData | ConvertTo-Json -Depth 10

        # 2. Fix the PowerShell 5.1 double-space colon bug
        $RawJson = $RawJson -replace '":\s+', '": '

        # 3. Recalculate perfect 4-space indents, stripping PS5.1's weird alignments
        $Indent = 0
        $CleanJson = @()
        foreach ($Line in ($RawJson -split "`r`n|`n")) {
            $Trimmed = $Line.Trim()
            
            # Decrease indent if line starts with a closing bracket/brace
            if ($Trimmed -match '^[\]\}]') { $Indent -= 4 }
            
            # Apply standard spaces
            $CleanJson += (" " * [Math]::Max(0, $Indent)) + $Trimmed
            
            # Increase indent if line ends with an opening bracket/brace
            if ($Trimmed -match '[\{\[]$') { $Indent += 4 }
        }
        $FinalJson = $CleanJson -join "`r`n"

        # 4. Save the perfectly formatted JSON
        $FinalJson | Set-Content -Path $JsonFilename -Encoding UTF8
        Write-Host "`nSuccessfully exported JSON report:`n - $JsonFilename" -ForegroundColor Green
    }
    catch {
        Write-Host "Error writing to $JsonFilename`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =============================================================================
# Main Execution Block
# =============================================================================
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

# 1. Setup & Authentication
Write-Host "=== CTD Assets Per CVE Exporter ==="
$CtdIp = (Read-Host "Enter CTD IP or hostname").Trim()
$Username = (Read-Host "Enter CTD username").Trim()
$SecurePassword = Read-Host "Enter CTD password" -AsSecureString
$Password = [System.Net.NetworkCredential]::new("", $SecurePassword).Password

$AuthToken = Get-Authentication -CtdIp $CtdIp -Username $Username -Password $Password

# 2. Collect Preferences
$TargetCve = Get-CveInput
$TimeFilter = Get-TimeFilter
$StartUtc = $TimeFilter.Start
$EndUtc = $TimeFilter.End

$FieldsSelection = Get-FieldsInput
$FieldsParam = $FieldsSelection.FieldsParam
$AdditionalFields = $FieldsSelection.AdditionalFields

$OutputFormat = Get-OutputPreference

# 3. Fetch Data
$RawVulnerabilities = Get-AssetVulnerabilities -CtdIp $CtdIp -AuthToken $AuthToken -TargetCve $TargetCve -StartUtc $StartUtc -EndUtc $EndUtc -FieldsParam $FieldsParam

# 4. Process & Export
if (-not $RawVulnerabilities -or $RawVulnerabilities.Count -eq 0) {
    Write-Host "`nNo vulnerabilities found matching those criteria. Exiting." -ForegroundColor Yellow
    exit 0
}

Write-Host "`nProcessing data..."
if ($OutputFormat -eq 'csv') {
    Export-ToCsv -Timestamp $Timestamp -RawData $RawVulnerabilities -AdditionalFields $AdditionalFields
}
elseif ($OutputFormat -eq 'json') {
    Export-ToJson -Timestamp $Timestamp -RawData $RawVulnerabilities -AdditionalFields $AdditionalFields
}

Write-Host "`nScript execution complete."