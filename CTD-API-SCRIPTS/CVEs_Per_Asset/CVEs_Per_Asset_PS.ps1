<#
=============================================================================
 Script Metadata
-----------------------------------------------------------------------------
 Description:
 This script connects to a Claroty CTD server, authenticates, and retrieves 
 a list of vulnerable assets, along with confirmed CVEs found by CTD per asset. Output is modularized
 and can be exported to either CSV or a nested JSON format based on user input.
 It also includes an optional time filter to only pull recently seen assets.
=============================================================================
#>

# Bypass SSL Certificate validation
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

function Get-RelativeTimeFilter {
    Write-Host "`n--- Time Filter ---"
    $DaysInput = (Read-Host "Pull assets last seen within how many days ago? (Leave blank for all time)").Trim()
    
    if ($DaysInput -match '^\d+$') {
        Write-Host "Filtering for assets last seen within the last $DaysInput days.`n"
        return $DaysInput
    }
    else {
        Write-Host "No time filter applied. Pulling all relevant assets.`n"
        return $null
    }
}

function Get-FieldsInput {
    Write-Host "`n--- Field Selection ---"
    $MandatoryFields = @('cve_id', 'asset_id', 'asset_name')
    
    $OptionalFields = @(
        'cvss_v3_score', 'epss_score', 'actively_exploited', 
        'advisory_names', 'vulnerability_type', 'detection_date', 'description'
    )

    Write-Host "Mandatory fields (Always included): cve_id, asset_id, asset_name"
    Write-Host "Optional fields to include:"
    
    for ($i = 0; $i -lt $OptionalFields.Count; $i++) {
        $Index = $i + 1
        $DisplayName = if ($OptionalFields[$i] -eq "advisory_names") { "advisory" } else { $OptionalFields[$i] }
        Write-Host ("  {0,2}. {1}" -f $Index, $DisplayName)
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

    $FieldsParam = $SelectedFields -join ",;$"
    return @{
        FieldsParam = $FieldsParam
        AdditionalFields = $AdditionalFields.ToArray()
    }
}

function Get-AssetIdFilter {
    param ([hashtable]$AssetInfo)

    Write-Host "`n--- Relevant Assets (Confirmed Vulnerabilities) ---"
    Write-Host ("{0,-10} | {1}" -f "Asset ID", "Asset Name")
    Write-Host ("-" * 45)
    
    foreach ($A_Id in $AssetInfo.Keys) {
        Write-Host ("{0,-10} | {1}" -f $A_Id, $AssetInfo[$A_Id].name)
    }
    Write-Host ("-" * 45)

    $TargetAsset = (Read-Host "`nEnter an Asset ID to filter by (or press Enter for all assets)").Trim()
    
    if ([string]::IsNullOrEmpty($TargetAsset)) {
        Write-Host "No asset filter applied. Processing all relevant assets.`n"
        return $null
    }
    
    foreach ($A_Id in $AssetInfo.Keys) {
        if ([string]$A_Id -eq $TargetAsset) {
            Write-Host ("Filtering for Asset ID: {0} ({1})`n" -f $A_Id, $AssetInfo[$A_Id].name)
            return [string]$A_Id
        }
    }
            
    Write-Host "Asset ID '$TargetAsset' not found in the relevant assets list. Proceeding with all assets.`n" -ForegroundColor Yellow
    return $null
}

function Get-Assets {
    param (
        [string]$CtdIp,
        [hashtable]$Headers,
        [string]$RelativeDays
    )
    
    Write-Host "Fetching relevant assets..."
    $AssetCveCounts = [ordered]@{}
    $AssetCveMapping = [ordered]@{}
    $AssetInfo = [ordered]@{}
    $Page = 1
    
    while ($true) {
        $QueryString = "?page=$Page&per_page=500&ghost__exact=false&special_hint__exact=0&site_id__exact=1&relevance__exact=1&fields=$([uri]::EscapeDataString('id,;$name'))"
        
        if (![string]::IsNullOrEmpty($RelativeDays)) {
            $QueryString += "&last_seen__relative_time=$RelativeDays"
        }

        $Uri = "https://$CtdIp/ranger/assets$QueryString"

        try {
            # Removed -Body parameter for GET request
            $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop
        }
        catch {
            Write-Host "Error fetching assets: $($_.Exception.Message)" -ForegroundColor Red
            break
        }
        
        if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
            foreach ($Asset in $Response.objects) {
                $A_id = if ($Asset.id) { $Asset.id } else { $Asset.asset_id }
                
                if (-not $A_id) { continue }
                $A_id_Str = [string]$A_id
                    
                $A_name = if ($Asset.name) { $Asset.name } elseif ($Asset.hostname) { $Asset.hostname } else { "Unknown" }
                $IpVal = if ($Asset.ip) { $Asset.ip } else { "" }
                
                $AssetInfo[$A_id_Str] = @{ 'name' = $A_name; 'ip' = $IpVal }
                $AssetCveCounts[$A_id_Str] = 0
                $AssetCveMapping[$A_id_Str] = @()
            }
            $Page++
        }
        else {
            break
        }
    }
            
    Write-Host ("Number of valid vulnerable assets tracked: {0}" -f $AssetInfo.Count)
    return @{
        Counts = $AssetCveCounts
        Mapping = $AssetCveMapping
        Info = $AssetInfo
    }
}

function Get-CVEs {
    param (
        [string]$CtdIp,
        [hashtable]$Headers,
        $AssetCveCounts,     # Removed [hashtable]
        $AssetCveMapping,    # Removed [hashtable]
        [string]$FieldsParam,
        [array]$AdditionalFields
    )
    
    Write-Host "Fetching confirmed CVEs for tracked assets..."
    
    $TotalAssets = $AssetCveMapping.Count
    $Index = 1
    
    # Snapshot the keys into a static array using @() to safely iterate
    $AssetKeys = @($AssetCveMapping.Keys)
    
    foreach ($A_id in $AssetKeys) {
        Write-Host "Processing Asset $Index/$TotalAssets | ID: $A_id..."
        $Page = 1
        
        while ($true) {
            $QueryString = "?page=$Page&per_page=500&site_id__exact=1&ghost__exact=false&special_hint__exact=0&relevance__exact=1&asset_id__exact=$($A_id)-1&fields=$([uri]::EscapeDataString($FieldsParam))"
            $Uri = "https://$CtdIp/ranger/asset-vulnerabilities$QueryString"
            
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop
            }
            catch {
                Write-Host "Error fetching CVEs for asset ${A_id}: $($_.Exception.Message)" -ForegroundColor Red
                break
            }
            
            if ($null -ne $Response.objects -and $Response.objects.Count -gt 0) {
                foreach ($Mapping in $Response.objects) {
                    $Cve_id = $Mapping.cve_id
                    if ($Cve_id) {
                        $AssetCveCounts[$A_id] += 1
                        
                        $VulnData = [ordered]@{ 'cve_id' = $Cve_id }
                        foreach ($Field in $AdditionalFields) {
                            $VulnData[$Field] = $Mapping.$Field
                        }
                        
                        $AssetCveMapping[$A_id] += [PSCustomObject]$VulnData
                    }
                }
                $Page++
            }
            else {
                break
            }
        }
        $Index++
    }
}

function Format-Value {
    param ($Value)
    
    if ($null -eq $Value) {
        return ""
    }
    
    # If the value is a PSCustomObject (the PS equivalent of a nested dictionary)
    if ($Value.GetType().Name -eq "PSCustomObject") {
        if ($null -ne $Value.value) {
            return [string]$Value.value
        }
        return [string]$Value
    }
    elseif ($Value -is [array]) {
        return ($Value -join ", ")
    }
    
    return [string]$Value
}

function Export-ToCsv {
    param (
        [string]$Timestamp,
        $AssetCveCounts,     # Removed [hashtable]
        $AssetCveMapping,    # Removed [hashtable]
        $AssetInfo,          # Removed [hashtable]
        [array]$AdditionalFields
    )
    
    $Csv1Filename = "Assets_CVE_Counts_List_$Timestamp.csv"
    try {
        $Csv1Data = @()
        foreach ($A_id in $AssetCveCounts.Keys) {
            $Name = if ($AssetInfo[$A_id].name) { $AssetInfo[$A_id].name } else { "Unknown" }
            $Csv1Data += [PSCustomObject]@{
                'Asset ID'   = $A_id
                'Asset Name' = $Name
                'CVE Count'  = $AssetCveCounts[$A_id]
            }
        }
        $Csv1Data | Export-Csv -Path $Csv1Filename -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Host "Error writing $Csv1Filename : $($_.Exception.Message)" -ForegroundColor Red
    }
            
    $Csv2Filename = "CVEs_Per_Assets_List_$Timestamp.csv"
    try {
        # Format the additional field headers (e.g. cvss_v3_score -> Cvss V3 Score)
        $TextInfo = (Get-Culture).TextInfo
        $FormattedAdditionalFields = $AdditionalFields | ForEach-Object { $TextInfo.ToTitleCase($_.Replace('_', ' ')) }
        
        $Csv2Data = @()
        
        foreach ($A_id in $AssetCveMapping.Keys) {
            $CveList = $AssetCveMapping[$A_id]
            if (-not $CveList -or $CveList.Count -eq 0) { continue }
            
            $Name = $AssetInfo[$A_id].name
            $ItemNum = 1
            
            foreach ($CveObj in $CveList) {
                $Row = [ordered]@{
                    'Asset ID'   = $A_id
                    'Asset Name' = $Name
                    'Item'       = $ItemNum
                    'CVE ID'     = $CveObj.cve_id
                }
                
                for ($i = 0; $i -lt $AdditionalFields.Count; $i++) {
                    $RawField = $AdditionalFields[$i]
                    $HeaderName = $FormattedAdditionalFields[$i]
                    $Row[$HeaderName] = Format-Value -Value $CveObj.$RawField
                }
                
                $Csv2Data += [PSCustomObject]$Row
                $ItemNum++
            }
        }
        
        if ($Csv2Data.Count -gt 0) {
            $Csv2Data | Export-Csv -Path $Csv2Filename -NoTypeInformation -Encoding UTF8
        }
    }
    catch {
        Write-Host "Error writing $Csv2Filename : $($_.Exception.Message)" -ForegroundColor Red
    }
                
    Write-Host "`nCSVs Exported:`n - $Csv1Filename`n - $Csv2Filename" -ForegroundColor Green
}

function Export-ToJson {
    param (
        [string]$Timestamp,
        $AssetCveMapping,    # Removed [hashtable]
        $AssetInfo           # Removed [hashtable]
    )
    
    $JsonFilename = "CVEs_Per_Assets_List_$Timestamp.json"
    $OutputData = @()
    
    foreach ($A_id in $AssetCveMapping.Keys) {
        $Cves = $AssetCveMapping[$A_id]
        if ($Cves -and $Cves.Count -gt 0) {
            $OutputData += [PSCustomObject]@{
                "asset id"        = $A_id
                "asset name"      = $AssetInfo[$A_id].name
                "cves count"      = $Cves.Count
                "vulnerabilities" = $Cves
            }
        }
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

Write-Host "=== Claroty CTD CVEs Per Asset Refined Script ==="

# 1. User Inputs
$CtdIp = (Read-Host "Enter CTD IP or hostname").Trim()
$Username = (Read-Host "Enter CTD username").Trim()
$SecurePassword = Read-Host "Enter CTD password" -AsSecureString
$Password = [System.Net.NetworkCredential]::new("", $SecurePassword).Password

$Headers = Get-Authentication -CtdIp $CtdIp -Username $Username -Password $Password

$FieldsSelection = Get-FieldsInput
$FieldsParam = $FieldsSelection.FieldsParam
$AdditionalFields = $FieldsSelection.AdditionalFields

$OutputFormat = Get-OutputPreference
$RelativeDays = Get-RelativeTimeFilter

# 2. Fetch Assets
$AssetData = Get-Assets -CtdIp $CtdIp -Headers $Headers -RelativeDays $RelativeDays
$AssetCveCounts = $AssetData.Counts
$AssetCveMapping = $AssetData.Mapping
$AssetInfo = $AssetData.Info

if ($AssetInfo.Count -eq 0) {
    Write-Host "No assets matched the criteria. Exiting script." -ForegroundColor Yellow
    exit 0
}
    
# 3. Prompt for Single Asset Filter
$SelectedAssetId = Get-AssetIdFilter -AssetInfo $AssetInfo

if ($null -ne $SelectedAssetId) {
    # Filter the hashtables to just the selected ID
    $FilteredCveCounts = @{ $SelectedAssetId = $AssetCveCounts[$SelectedAssetId] }
    $FilteredCveMapping = @{ $SelectedAssetId = $AssetCveMapping[$SelectedAssetId] }
    $FilteredAssetInfo = @{ $SelectedAssetId = $AssetInfo[$SelectedAssetId] }
    
    $AssetCveCounts = $FilteredCveCounts
    $AssetCveMapping = $FilteredCveMapping
    $AssetInfo = $FilteredAssetInfo
}

# 4. Fetch CVEs for Selected Asset(s)
Get-CVEs -CtdIp $CtdIp -Headers $Headers -AssetCveCounts $AssetCveCounts -AssetCveMapping $AssetCveMapping -FieldsParam $FieldsParam -AdditionalFields $AdditionalFields

# 5. Validation & Export
$AssetsWithVulns = 0
foreach ($A_id in $AssetCveMapping.Keys) {
    if ($AssetCveMapping[$A_id] -and $AssetCveMapping[$A_id].Count -gt 0) {
        $AssetsWithVulns++
    }
}

Write-Host "`nTotal assets with confirmed vulnerabilities processed: $AssetsWithVulns"

if ($OutputFormat -eq 'csv') {
    Export-ToCsv -Timestamp $Timestamp -AssetCveCounts $AssetCveCounts -AssetCveMapping $AssetCveMapping -AssetInfo $AssetInfo -AdditionalFields $AdditionalFields
}
elseif ($OutputFormat -eq 'json') {
    Export-ToJson -Timestamp $Timestamp -AssetCveMapping $AssetCveMapping -AssetInfo $AssetInfo
}
    
Write-Host "`nScript execution complete."