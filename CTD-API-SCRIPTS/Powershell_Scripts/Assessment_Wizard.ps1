<#
=============================================================================
Assessment Wizard
-----------------------------------------------------------------------------
Description:
This wizard allows a user to either generate a new asset baseline from a 
Claroty CTD server, or compare an existing baseline against a second file 
or a live CTD scan. 
Outputs supported: CSV, JSON, TXT, MD
=============================================================================
#>

# Disable SSL/TLS warnings globally (Equivalent to urllib3.disable_warnings())
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Read-Password {
    $securePassword = Read-Host "Enter CTD password" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    return $plainPassword
}

# -----------------------------------------------------------------------------
# Core & Authentication Functions
# -----------------------------------------------------------------------------

function Authenticate-CTD {
    param($ctd_ip, $username, $password)

    Write-Host "`nAuthenticating to CTD at https://$ctd_ip..."
    $auth_payload = @{ username = $username; password = $password } | ConvertTo-Json
    $headers = @{ "Content-type" = "application/json"; "Accept" = "text/plain" }
    
    try {
        $response = Invoke-RestMethod -Uri "https://$ctd_ip/auth/authenticate" -Method Post -Headers $headers -Body $auth_payload -ErrorAction Stop
    } catch {
        Write-Host "Connection Error: $_" -ForegroundColor Red
        exit 1
    }

    if ($null -ne $response.error) {
        Write-Host "Authentication Failed: $($response.error)" -ForegroundColor Red
        exit 1
    }

    Write-Host "Successful Login.`n" -ForegroundColor Green
    
    return @{
        'Authorization' = $response.token
        'Content-Type' = 'application/json'
    }
}

function Get-OutputPreference {
    param([bool]$is_delta = $false)

    $prompt_text = if ($is_delta) { "Would you like the Delta Report output in CSV, JSON, TXT, or MD format?" } else { "Would you like the output in CSV, JSON, TXT, or MD format?" }
    
    while ($true) {
        $choice = (Read-Host "`n$prompt_text (Enter 'csv', 'json', 'txt', or 'md')").Trim().ToLower()
        if ($choice -in @('csv', 'json', 'txt', 'md')) {
            return $choice
        }
        Write-Host "Invalid input. Please type 'csv', 'json', 'txt', or 'md'."
    }
}

function Get-FieldsInput {
    Write-Host "`n--- Field Selection ---"
    
    $mandatory_fields = @('id', 'name', 'virtual_zone_name', 'asset_type', 'criticality', 'purdue_level')
    $optional_fields = @(
        'ipv4', 'ipv6', 'mac', 'os', 'model', 'vendor', 'firmware', 
        'site_id', 'resource_id', 'timestamp', 'last_updated', 'approved', 
        'valid', 'ghost', 'parsed', 'special_hint', 'risk_level', 
        'last_entity_seen', 'site_name', 'network_id', 'subnet_id', 
        'virtual_zone_id', 'active_queries_names', 
        'active_tasks_names', 'first_seen', 'vlan', 'fdl', 
        'address', 'gateway', 'class_type', 'hostname', 
        'plc_slots', 'project_parsed', 'serial_number', 
        'domain_workgroup', 'default_gateway', 'edge_last_run', 'edge_id', 
        'installed_antivirus', 'has_interfaces', 'old_ips', 'state', 
        'custom_informations', 'patch_count', 'code_sections', 
        'installed_programs_count', 'usb_devices_count', 'os_build', 
        'os_architecture', 'os_service_pack', 'asset_insight', 'display_name', 
        'protocol', 'last_seen', 'num_alerts', 'children', 'network', 'subnet', 
        'subnet_tag', 'subnet_type', 'custom_attributes', 'insight_names', 'risk_score'
    )

    Write-Host "Mandatory fields (Always included): $($mandatory_fields -join ', ')"
    Write-Host "Optional fields to include:"
    
    for ($i = 0; $i -lt $optional_fields.Count; $i++) {
        $num = $i + 1
        Write-Host "  $num. $($optional_fields[$i])"
    }

    $selections = (Read-Host "`nEnter a comma-separated list of numbers to include (or press Enter to just pull mandatory fields)").Trim()
    
    $selected_fields = [System.Collections.Generic.List[string]]::new()
    $mandatory_fields | ForEach-Object { $selected_fields.Add($_) }

    if (-not [string]::IsNullOrEmpty($selections)) {
        try {
            $indices = $selections -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            foreach ($index in $indices) {
                $idx = [int]$index
                if ($idx -ge 1 -and $idx -le $optional_fields.Count) {
                    $field_name = $optional_fields[$idx - 1]
                    if (-not $selected_fields.Contains($field_name)) {
                        $selected_fields.Add($field_name)
                    }
                }
            }
        } catch {
            Write-Host "Error parsing field selection. Defaulting to mandatory fields only."
        }
    }

    return $selected_fields.ToArray()
}

function Fetch-AllAssets {
    param($ctd_ip, $headers, $fieldnames)

    Write-Host "`nFetching Assets from CTD..."
    $parsed_assets = [System.Collections.Generic.List[psobject]]::new()
    $page = 1
    $fields_param = $fieldnames -join ",;$"
    
    while ($true) {
        Write-Host " - Processing page $page..."
        
        $uri = "https://$ctd_ip/ranger/assets?page=$page&per_page=500&ghost__exact=false&valid__exact=true&special_hint__exact=0&site_id__exact=1&fields=$fields_param"
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        
        if ($null -ne $response.objects -and $response.objects.Count -gt 0) {
            foreach ($asset in $response.objects) {
                $row_data = [ordered]@{}
                foreach ($field in $fieldnames) {
                    $value = $asset.$field
                    if ($null -eq $value) {
                        $row_data[$field] = "None"
                    } elseif ($value -is [array]) {
                        $row_data[$field] = if ($value.Count -eq 0) { "None" } else { $value -join ", " }
                    } else {
                        $strValue = [string]$value
                        $row_data[$field] = if ([string]::IsNullOrWhiteSpace($strValue)) { "None" } else { $strValue.Trim() }
                    }
                }
                $parsed_assets.Add([pscustomobject]$row_data)
            }
            $page++
        } else {
            Write-Host "Asset extraction complete.`n"
            break
        }
    }
    
    return $parsed_assets.ToArray()
}

# -----------------------------------------------------------------------------
# Baseline Generation (Option 1)
# -----------------------------------------------------------------------------

function Export-ToCsv {
    param($timestamp, $parsed_assets, $fieldnames)
    
    $filename = "total_assets_$timestamp.csv"
    
    # In PowerShell, PSCustomObjects naturally export via Export-Csv
    # Using Select-Object $fieldnames ensures strict order matching
    $parsed_assets | Select-Object $fieldnames | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8
    
    Write-Host "Data written to file: $filename"
}

function Export-ToJson {
    param($timestamp, $parsed_assets, $fieldnames)
    
    $filename = "total_assets_$timestamp.json"
    $output_data = @()
    
    foreach ($asset in $parsed_assets) {
        $formatted_object = [ordered]@{}
        foreach ($field in $fieldnames) {
            $key = if ($field -eq "id") { "asset id" } else { $field }
            $val = $asset.$field
            $formatted_object[$key] = if ($null -eq $val) { "None" } else { $val }
        }
        $output_data += [pscustomobject]$formatted_object
    }
    
    $output_data | ConvertTo-Json -Depth 10 | Set-Content -Path $filename -Encoding UTF8
    Write-Host "Data written to file: $filename"
}

function Export-ToTxt {
    param($timestamp, $parsed_assets, $fieldnames)
    
    $filename = "total_assets_$timestamp.txt"
    $stream = [System.IO.StreamWriter]::new((Resolve-Path -Path "." | Select-Object -ExpandProperty Path) + "\$filename")
    
    foreach ($asset in $parsed_assets) {
        $stream.WriteLine("-" * 40)
        foreach ($field in $fieldnames) {
            $key = if ($field -eq "id") { "asset id" } else { $field }
            $textInfo = (Get-Culture).TextInfo
            $formattedKey = $textInfo.ToTitleCase($key)
            $val = $asset.$field
            $valStr = if ($null -eq $val) { "None" } else { $val }
            $stream.WriteLine($formattedKey + ": " + $valStr)
        }
    }
    $stream.WriteLine("-" * 40)
    $stream.Close()
    
    Write-Host "Data written to file: $filename"
}

function Export-ToMd {
    param($timestamp, $parsed_assets, $fieldnames)
    
    $filename = "total_assets_$timestamp.md"
    $stream = [System.IO.StreamWriter]::new((Resolve-Path -Path "." | Select-Object -ExpandProperty Path) + "\$filename")
    
    $stream.WriteLine("# Baseline Asset Report`n")
    
    # Write headers
    $headers = $fieldnames | ForEach-Object { if ($_ -eq "id") { "asset id" } else { $_ } }
    $stream.WriteLine("| " + ($headers -join " | ") + " |")
    $dividers = $headers | ForEach-Object { "---" }
    $stream.WriteLine("|" + ($dividers -join "|") + "|")
    
    # Write rows
    foreach ($asset in $parsed_assets) {
        $row = $fieldnames | ForEach-Object {
            $val = $asset.$_
            $valStr = if ($null -eq $val) { "None" } else { [string]$val }
            $valStr.Replace("|", "\|")
        }
        $stream.WriteLine("| " + ($row -join " | ") + " |")
    }
    
    $stream.Close()
    Write-Host "Data written to file: $filename"
}

function Invoke-GenerateBaseline {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    Write-Host "`n--- Generate Baseline ---"
    $ctd_ip = (Read-Host "Enter CTD IP or hostname").Trim()
    $username = (Read-Host "Enter CTD username").Trim()
    $password = Read-Password
    
    $headers = Authenticate-CTD -ctd_ip $ctd_ip -username $username -password $password

    $output_format = Get-OutputPreference -is_delta $false
    $asset_fieldnames = Get-FieldsInput

    $parsed_assets = Fetch-AllAssets -ctd_ip $ctd_ip -headers $headers -fieldnames $asset_fieldnames
    $total_assets = @($parsed_assets).Count

    if ($total_assets -gt 0) {
        if ($output_format -eq 'csv') { Export-ToCsv -timestamp $timestamp -parsed_assets $parsed_assets -fieldnames $asset_fieldnames }
        elseif ($output_format -eq 'json') { Export-ToJson -timestamp $timestamp -parsed_assets $parsed_assets -fieldnames $asset_fieldnames }
        elseif ($output_format -eq 'txt') { Export-ToTxt -timestamp $timestamp -parsed_assets $parsed_assets -fieldnames $asset_fieldnames }
        elseif ($output_format -eq 'md') { Export-ToMd -timestamp $timestamp -parsed_assets $parsed_assets -fieldnames $asset_fieldnames }
    } else {
        Write-Host "No valid assets found to export."
    }

    Write-Host ("-" * 35)
    Write-Host "Summary of Asset Processing"
    Write-Host ("-" * 35)
    Write-Host "Total valid assets saved : $( '{0:N0}' -f $total_assets )"
    Write-Host ("-" * 35)
}

# -----------------------------------------------------------------------------
# Baseline Comparison (Option 2)
# -----------------------------------------------------------------------------

function Load-JsonSnapshot {
    param($filepath)
    
    if (-not (Test-Path $filepath)) {
        Write-Host "Error: File not found - $filepath" -ForegroundColor Red
        exit 1
    }
    try {
        $content = Get-Content -Path $filepath -Raw -Encoding UTF8
        return $content | ConvertFrom-Json
    } catch {
        Write-Host "Error: Invalid JSON format in - $filepath" -ForegroundColor Red
        exit 1
    }
}

function Build-AssetDictionary {
    param($asset_list)
    
    $asset_dict = @{}
    foreach ($asset in $asset_list) {
        $asset_id = $asset."asset id"
        if ($null -ne $asset_id -and $asset_id -ne "None") {
            $asset_dict[[string]$asset_id] = $asset
        }
    }
    return $asset_dict
}

function Compare-Snapshots {
    param($old_assets, $new_assets)
    
    $old_keys = [System.Collections.Generic.HashSet[string]]::new([string[]]$old_assets.Keys)
    $new_keys = [System.Collections.Generic.HashSet[string]]::new([string[]]$new_assets.Keys)

    $added_keys = [System.Collections.Generic.HashSet[string]]::new($new_keys)
    $added_keys.ExceptWith($old_keys)

    $removed_keys = [System.Collections.Generic.HashSet[string]]::new($old_keys)
    $removed_keys.ExceptWith($new_keys)

    $intersect_keys = [System.Collections.Generic.HashSet[string]]::new($old_keys)
    $intersect_keys.IntersectWith($new_keys)

    $added_assets = [System.Collections.Generic.List[psobject]]::new()
    foreach ($k in $added_keys) { $added_assets.Add($new_assets[$k]) }
    
    $removed_assets = [System.Collections.Generic.List[psobject]]::new()
    foreach ($k in $removed_keys) { $removed_assets.Add($old_assets[$k]) }
    
    $changed_assets = [System.Collections.Generic.List[psobject]]::new()

    $fields_to_monitor = @('name', 'asset_type', 'virtual_zone_name', 'criticality', 'purdue_level')

    foreach ($key in $intersect_keys) {
        $old_asset = $old_assets[$key]
        $new_asset = $new_assets[$key]
        $changes = [ordered]@{}

        foreach ($field in $fields_to_monitor) {
            $old_val = if ($null -ne $old_asset.$field) { [string]$old_asset.$field } else { "None" }
            $new_val = if ($null -ne $new_asset.$field) { [string]$new_asset.$field } else { "None" }
            $old_val = $old_val.Trim()
            $new_val = $new_val.Trim()

            if ($old_val -ne $new_val) {
                $changes[$field] = @{ "old_value" = $old_val; "new_value" = $new_val }
            }
        }

        if ($changes.Count -gt 0) {
            $assetName = if ($null -ne $new_asset.name) { $new_asset.name } else { "Unknown" }
            $changed_assets.Add([pscustomobject]@{
                "asset id" = $key
                "asset_name" = $assetName
                "changes" = $changes
            })
        }
    }

    return $added_assets, $removed_assets, $changed_assets
}

function Export-DeltaToJson {
    param($added, $removed, $changed)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "delta_report_$timestamp.json"
    
    $report = [ordered]@{
        "metadata" = [ordered]@{
            "timestamp" = $timestamp
            "summary" = [ordered]@{
                "total_added" = @($added).Count
                "total_removed" = @($removed).Count
                "total_changed" = @($changed).Count
            }
        }
        "added_assets" = $added
        "removed_assets" = $removed
        "changed_assets" = $changed
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $filename -Encoding UTF8
    Write-Host "`n[+] Delta JSON report successfully written to: $filename"
}

function Export-DeltaToCsv {
    param($added, $removed, $changed)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "delta_report_$timestamp.csv"
    
    $rows = [System.Collections.Generic.List[psobject]]::new()
    
    foreach ($asset in $added) {
        $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
        $rows.Add([pscustomobject]@{
            'asset id' = $asset."asset id"
            'asset_name' = $name
            'status' = 'Added'
            'change_details' = 'New Asset'
        })
    }
    foreach ($asset in $removed) {
        $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
        $rows.Add([pscustomobject]@{
            'asset id' = $asset."asset id"
            'asset_name' = $name
            'status' = 'Removed'
            'change_details' = 'Asset Removed'
        })
    }
    foreach ($asset in $changed) {
        $name = if ($null -ne $asset.asset_name) { $asset.asset_name } else { "Unknown" }
        
        $changes_list = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $asset.changes.Keys) {
            $v = $asset.changes[$key]
            $changes_list.Add($key + ": '" + $v.old_value + "' -> '" + $v.new_value + "'")
        }
        
        $rows.Add([pscustomobject]@{
            'asset id' = $asset."asset id"
            'asset_name' = $name
            'status' = 'Changed'
            'change_details' = ($changes_list -join " | ")
        })
    }
    
    if ($rows.Count -gt 0) {
        $rows | Select-Object 'asset id', 'asset_name', 'status', 'change_details' | Export-Csv -Path $filename -NoTypeInformation -Encoding UTF8
    }
    Write-Host "`n[+] Delta CSV report successfully written to: $filename"
}

function Export-DeltaToTxt {
    param($added, $removed, $changed)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "delta_report_$timestamp.txt"
    $stream = [System.IO.StreamWriter]::new((Resolve-Path -Path "." | Select-Object -ExpandProperty Path) + "\$filename")
    
    $stream.WriteLine("=" * 40)
    $stream.WriteLine(" DELTA REPORT")
    $stream.WriteLine("=" * 40 + "`n")
    $stream.WriteLine("Assets Added   : $(@($added).Count)")
    $stream.WriteLine("Assets Removed : $(@($removed).Count)")
    $stream.WriteLine("Assets Changed : $(@($changed).Count)`n")
    
    $stream.WriteLine("--- ADDED ASSETS ---")
    if (@($added).Count -eq 0) { $stream.WriteLine("None") }
    foreach ($asset in $added) {
        $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
        $stream.WriteLine("ID: $($asset.'asset id') | Name: $name")
    }
    
    $stream.WriteLine("`n--- REMOVED ASSETS ---")
    if (@($removed).Count -eq 0) { $stream.WriteLine("None") }
    foreach ($asset in $removed) {
        $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
        $stream.WriteLine("ID: $($asset.'asset id') | Name: $name")
    }
    
    $stream.WriteLine("`n--- CHANGED ASSETS ---")
    if (@($changed).Count -eq 0) { $stream.WriteLine("None") }
    foreach ($asset in $changed) {
        $name = if ($null -ne $asset.asset_name) { $asset.asset_name } else { "Unknown" }
        $changes_list = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $asset.changes.Keys) {
            $v = $asset.changes[$key]
            $changes_list.Add($key + ": '" + $v.old_value + "' -> '" + $v.new_value + "'")
        }
        $stream.WriteLine("ID: $($asset.'asset id') | Name: $name")
        $stream.WriteLine("  Changes: $( $changes_list -join ' | ' )`n")
    }
    
    $stream.Close()
    Write-Host "`n[+] Delta TXT report successfully written to: $filename"
}

function Export-DeltaToMd {
    param($added, $removed, $changed)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "delta_report_$timestamp.md"
    $stream = [System.IO.StreamWriter]::new((Resolve-Path -Path "." | Select-Object -ExpandProperty Path) + "\$filename")
    
    $stream.WriteLine("# Baseline Delta Report`n")
    $stream.WriteLine("## Summary")
    $stream.WriteLine("- **Assets Added**: $(@($added).Count)")
    $stream.WriteLine("- **Assets Removed**: $(@($removed).Count)")
    $stream.WriteLine("- **Assets Changed**: $(@($changed).Count)`n")
    
    $stream.WriteLine("## Added Assets")
    if (@($added).Count -gt 0) {
        $stream.WriteLine("| Asset ID | Name |`n|---|---|")
        foreach ($asset in $added) {
            $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
            $stream.WriteLine("| $($asset.'asset id') | $name |")
        }
    } else {
        $stream.WriteLine("*No assets added.*`n")
    }
    
    $stream.WriteLine("`n## Removed Assets")
    if (@($removed).Count -gt 0) {
        $stream.WriteLine("| Asset ID | Name |`n|---|---|")
        foreach ($asset in $removed) {
            $name = if ($null -ne $asset.name) { $asset.name } else { "Unknown" }
            $stream.WriteLine("| $($asset.'asset id') | $name |")
        }
    } else {
        $stream.WriteLine("*No assets removed.*`n")
    }
    
    $stream.WriteLine("`n## Changed Assets")
    if (@($changed).Count -gt 0) {
        $stream.WriteLine("| Asset ID | Name | Changes |`n|---|---|---|")
        foreach ($asset in $changed) {
            $name = if ($null -ne $asset.asset_name) { $asset.asset_name } else { "Unknown" }
            
            $changes_list = [System.Collections.Generic.List[string]]::new()
            foreach ($key in $asset.changes.Keys) {
                $v = $asset.changes[$key]
                $changes_list.Add("**${key}**: $($v.old_value) &rarr; $($v.new_value)")
            }
            $stream.WriteLine("| $($asset.'asset id') | $name | $($changes_list -join '<br>') |")
        }
    } else {
        $stream.WriteLine("*No assets changed.*`n")
    }
    
    $stream.Close()
    Write-Host "`n[+] Delta MD report successfully written to: $filename"
}

function Summarize-AndExportDelta {
    param($added, $removed, $changed, $total_new_assets, $output_format)
    
    Write-Host ("-" * 40)
    Write-Host "Delta Summary"
    Write-Host ("-" * 40)
    Write-Host "Total Current Assets Pulled/Read : $( '{0:N0}' -f $total_new_assets )"
    Write-Host "Assets Added                     : $( '{0:N0}' -f @($added).Count )"
    Write-Host "Assets Removed                   : $( '{0:N0}' -f @($removed).Count )"
    Write-Host "Assets Changed                   : $( '{0:N0}' -f @($changed).Count )"
    Write-Host ("-" * 40)

    if ((@($added).Count -gt 0) -or (@($removed).Count -gt 0) -or (@($changed).Count -gt 0)) {
        if ($output_format -eq 'csv') { Export-DeltaToCsv -added $added -removed $removed -changed $changed }
        elseif ($output_format -eq 'json') { Export-DeltaToJson -added $added -removed $removed -changed $changed }
        elseif ($output_format -eq 'txt') { Export-DeltaToTxt -added $added -removed $removed -changed $changed }
        elseif ($output_format -eq 'md') { Export-DeltaToMd -added $added -removed $removed -changed $changed }
    } else {
        Write-Host "No differences found."
    }
}

function Invoke-CompareBaseline {
    Write-Host "`n--- Compare Baseline ---"
    $old_filepath = (Read-Host "Enter path to the OG baseline file (JSON file)").Trim()
    
    Write-Host "Loading original baseline..."
    $old_data = Load-JsonSnapshot -filepath $old_filepath

    Write-Host "`nSelect comparison target:"
    Write-Host "1. Select another file (Source File)"
    Write-Host "2. Select live scan (CTD)"
    
    $target_choice = (Read-Host "`nSelect an option (1 or 2)").Trim()

    if ($target_choice -eq '1') {
        $new_filepath = (Read-Host "Enter path to the NEW baseline file (JSON file)").Trim()
        Write-Host "Loading new baseline..."
        $new_data = Load-JsonSnapshot -filepath $new_filepath
        
        $output_format = Get-OutputPreference -is_delta $true

        Write-Host "Building asset indices for comparison..."
        $old_dict = Build-AssetDictionary -asset_list $old_data
        $new_dict = Build-AssetDictionary -asset_list $new_data
        
        Write-Host "Calculating differences (Added, Removed, Changed)..."
        $added, $removed, $changed = Compare-Snapshots -old_assets $old_dict -new_assets $new_dict
        
        Summarize-AndExportDelta -added $added -removed $removed -changed $changed -total_new_assets @($new_data).Count -output_format $output_format

    } elseif ($target_choice -eq '2') {
        $ctd_ip = (Read-Host "`nEnter CTD IP or hostname for Live Pull").Trim()
        $username = (Read-Host "Enter CTD username").Trim()
        $password = Read-Password
        
        $headers = Authenticate-CTD -ctd_ip $ctd_ip -username $username -password $password

        $output_format = Get-OutputPreference -is_delta $true
        $asset_fieldnames = Get-FieldsInput

        $raw_live_assets = Fetch-AllAssets -ctd_ip $ctd_ip -headers $headers -fieldnames $asset_fieldnames
        $total_live_assets = @($raw_live_assets).Count
        
        if ($total_live_assets -eq 0) {
            Write-Host "No live assets found. Exiting."
            exit 0
        }

        $formatted_live_assets = @()
        foreach ($asset in $raw_live_assets) {
            $formatted_object = [ordered]@{}
            foreach ($field in $asset_fieldnames) {
                $key = if ($field -eq "id") { "asset id" } else { $field }
                $val = $asset.$field
                $formatted_object[$key] = if ($null -eq $val) { "None" } else { $val }
            }
            $formatted_live_assets += [pscustomobject]$formatted_object
        }

        Write-Host "Building asset indices for comparison..."
        $old_dict = Build-AssetDictionary -asset_list $old_data
        $new_dict = Build-AssetDictionary -asset_list $formatted_live_assets

        Write-Host "Calculating differences (Added, Removed, Changed)..."
        $added, $removed, $changed = Compare-Snapshots -old_assets $old_dict -new_assets $new_dict

        Summarize-AndExportDelta -added $added -removed $removed -changed $changed -total_new_assets $total_live_assets -output_format $output_format
    } else {
        Write-Host "Invalid option selected. Exiting."
    }
}

# -----------------------------------------------------------------------------
# Main Wizard Loop
# -----------------------------------------------------------------------------

function Main {
    Write-Host ("=" * 40)
    Write-Host "          ASSESSMENT WIZARD          "
    Write-Host ("=" * 40)
    Write-Host "1. Generate Baseline"
    Write-Host "2. Compare Baseline"
    Write-Host ("-" * 40)
    
    $choice = (Read-Host "Select an option (1 or 2)").Trim()
    
    if ($choice -eq '1') {
        Invoke-GenerateBaseline
    } elseif ($choice -eq '2') {
        Invoke-CompareBaseline
    } else {
        Write-Host "Invalid selection. Exiting."
    }

    Write-Host "`nScript execution complete."
}

# Entry Point
Main