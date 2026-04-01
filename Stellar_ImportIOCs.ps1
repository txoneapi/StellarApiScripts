#Requires -Version 5.1
# ==============================================================================
# FILE      : Stellar_ImportIOCs.ps1
# CREATED   : 2026-04-01
# PURPOSE   : Reads a list of file hashes (IOCs) from IOCs.csv and adds each
#             one as a User-Defined Suspicious Object (UDSO) in TXOne StellarOne.
# ==============================================================================

<#
.SYNOPSIS
    Imports file-hash IOCs from a CSV file into StellarOne as User-Defined
    Suspicious Objects (UDSO).

.DESCRIPTION
    Reads IOCs.csv (hash, description per line) and merges each hash into the
    global policy's userDefinedSuspiciousObjects list for each active product
    type (StellarProtect and StellarProtect Legacy Mode).

    How it works:
      1. Reads the StellarOne server address and API key from StellarOne.conf.
      2. Parses the CSV file; skips blank lines, comments, and MD5 hashes.
      3. For each product type (SP, SPLM), GETs the current global policy.
      4. Merges the new hashes into the existing UDSO list (no duplicates).
      5. PUTs the updated policy back.

    Supported hash types (StellarOne API limitation):
      SHA-1   -- 40 hex characters
      SHA-256 -- 64 hex characters
      MD5 is NOT supported by the StellarOne UDSO API and will be skipped.

    NOTE: StellarOne does not support a per-hash BLOCK/LOG action.
      The action is a policy-level setting configured in the StellarOne
      console.  The 'action' column in the CSV is accepted for documentation
      but is NOT sent to the API.

    API endpoints used:
      GET /api/v1/policy/global/{product_code}  - Read current global policy
      PUT /api/v1/policy/global                 - Write updated global policy

.PARAMETER CsvPath
    Path to the IOC CSV file.  Defaults to IOCs.csv in the same folder as
    this script.

.EXAMPLE
    .\Stellar_ImportIOCs.ps1

    Imports hashes from IOCs.csv in the script folder.

.EXAMPLE
    .\Stellar_ImportIOCs.ps1 -CsvPath "C:\IOCs\campaign_xyz.csv"

    Imports hashes from the specified CSV file.

.NOTES
    Prerequisites:
      - PowerShell 5.1 or later (built into Windows 10 / Server 2016+)
      - StellarOne.conf  must be in the same folder as this script
      - Network access to the StellarOne management server
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               HelpMessage = "Path to the IOC CSV file.  Defaults to IOCs.csv in the script folder.")]
    [string]$CsvPath = ""
)

$ErrorActionPreference = "Stop"


# ==============================================================================
# SECTION 1 - READ CONFIGURATION FILES
# ==============================================================================
# Rather than hard-coding the server address and API key directly in this
# script (which would be a security risk if the script is shared), we read
# them from a config file that lives alongside the script.
#
#   StellarOne.conf  ->  contains the URL and API key for StellarOne

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ConfPath  = Join-Path $ScriptDir "StellarOne.conf"

if (-not (Test-Path $ConfPath)) {
    Write-Error ("Required configuration file not found: $ConfPath`n" +
                 "Please copy stellarOne_example.conf to StellarOne.conf and fill in your values.")
    exit 1
}

$ConfContent = Get-Content $ConfPath -Raw

if ($ConfContent -match 'StellarOneURL="([^"]+)"') {
    $BaseUrl = $Matches[1].TrimEnd('/')
} else {
    Write-Error ("Could not read the StellarOne server URL from: $ConfPath`n" +
                 'Expected a line like:  StellarOneURL="https://192.168.1.1"')
    exit 1
}

if ($ConfContent -match 'ApiKey="([^"]+)"') {
    $ApiKey = $Matches[1]
} else {
    Write-Error ("Could not read the API key from: $ConfPath`n" +
                 'Expected a line like:  ApiKey="abc123..."')
    exit 1
}

$KeyPreview = $ApiKey.Substring(0, [Math]::Min(8, $ApiKey.Length))

# Resolve CSV path: use the parameter if provided, else default to IOCs.csv.
if ($CsvPath -eq "") {
    $CsvPath = Join-Path $ScriptDir "IOCs.csv"
}

if (-not (Test-Path $CsvPath)) {
    Write-Error ("IOC file not found: $CsvPath`n" +
                 "Create the file or pass its path via -CsvPath.")
    exit 1
}

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  StellarOne - Import IOCs  (PowerShell)" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  Server           : $BaseUrl"
Write-Host "  API key (first 8): $KeyPreview..."
Write-Host "  IOC file         : $CsvPath"
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""


# ==============================================================================
# SECTION 2 - TRUST THE SERVER'S SSL/TLS CERTIFICATE
# ==============================================================================
# StellarOne ships with a self-signed TLS certificate.  By default, PowerShell
# refuses to connect to servers whose certificate was not issued by a trusted
# Certificate Authority (CA).
#
# The code below temporarily tells PowerShell to trust all certificates for the
# rest of this session.  This is acceptable on a private management network but
# should NOT be used in security-sensitive or internet-facing environments.

if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate cert,
            WebRequest request, int certProblem) { return true; }
    }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12


# ==============================================================================
# SECTION 3 - DEFINE THE COMMON REQUEST HEADERS
# ==============================================================================
# Every HTTP request sent to StellarOne must carry an Authorization header
# containing the API key.

$Headers = @{
    "Authorization" = $ApiKey
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}


# ==============================================================================
# SECTION 4 - HELPER FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# Function : Invoke-StellarAPI
# Purpose  : Central function that sends any HTTP request to StellarOne and
#            returns the parsed JSON response as a PowerShell object.
#
# Parameters:
#   Method    - "GET" or "PUT"
#   Endpoint  - URL path, e.g. "/api/v1/policy/global"
#   Body      - Optional hashtable that becomes the JSON request body
#   Allow404  - If $true, returns $null on HTTP 404 instead of throwing
# ------------------------------------------------------------------------------
function Invoke-StellarAPI {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET","PUT")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [hashtable]$Body    = $null,
        [bool]$Allow404     = $false
    )

    $Url    = "$BaseUrl$Endpoint"
    $Params = @{
        Method      = $Method
        Uri         = $Url
        Headers     = $Headers
        ContentType = "application/json"
        ErrorAction = "Stop"
    }

    if ($null -ne $Body) {
        # -Depth 20 ensures deeply nested policy objects are fully serialised.
        $Params["Body"] = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    try {
        return Invoke-RestMethod @Params
    }
    catch {
        $StatusCode = 0
        if ($null -ne $_.Exception.Response) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($Allow404 -and $StatusCode -eq 404) {
            return $null
        }

        $ErrorDetail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $Parsed      = $_.ErrorDetails.Message | ConvertFrom-Json
                $ErrorDetail = $Parsed | ConvertTo-Json -Depth 3
            } catch { }
        }

        Write-Error "API call failed: $Method $Endpoint  |  HTTP $StatusCode  |  $ErrorDetail"
        throw
    }
}


# ------------------------------------------------------------------------------
# Function : Get-GlobalPolicy
# Purpose  : Retrieves the current global policy for a given product type.
#
# Parameters:
#   ProductCode - "PRODUCT_SP" or "PRODUCT_SPLM"
#
# Returns  : The policy response object, or $null if no policy exists.
# ------------------------------------------------------------------------------
function Get-GlobalPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProductCode
    )

    return Invoke-StellarAPI -Method "GET" `
        -Endpoint "/api/v1/policy/global/$ProductCode" `
        -Allow404 $true
}


# ------------------------------------------------------------------------------
# Function : Get-UdsoList
# Purpose  : Extracts the existing UDSO list from a GET global policy response.
#
# Parameters:
#   PolicyResponse - The object returned by Get-GlobalPolicy
#   PolicyKey      - "spPolicy" or "splmPolicy"
#
# Returns  : An array of existing UDSO objects (may be empty).
# ------------------------------------------------------------------------------
function Get-UdsoList {
    param(
        [object]$PolicyResponse,
        [string]$PolicyKey
    )

    if ($null -eq $PolicyResponse) { return @() }

    $Inner = $PolicyResponse.$PolicyKey
    if ($null -eq $Inner) { return @() }

    $Udso = $Inner.userDefinedSuspiciousObjects
    if ($null -eq $Udso -or $null -eq $Udso.list) { return @() }

    return @($Udso.list)
}


# ------------------------------------------------------------------------------
# Function : Merge-Iocs
# Purpose  : Merges new IOC entries into the existing UDSO list.
#
# Duplicates are detected by comparing hash values (case-insensitive).
# Existing entries are preserved unchanged; only new hashes are appended.
#
# Parameters:
#   ExistingList - Array of UDSO objects already in the policy
#   NewIocs      - Array of [PSCustomObject]@{Value; Notes; Type} to add
#
# Returns  : [PSCustomObject]@{MergedList; AddedCount; SkippedCount}
# ------------------------------------------------------------------------------
function Merge-Iocs {
    param(
        [array]$ExistingList,
        [array]$NewIocs
    )

    # Build a hash set of existing values for fast duplicate detection.
    $ExistingValues = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($Entry in $ExistingList) {
        if ($Entry.value) { $ExistingValues.Add($Entry.value) | Out-Null }
    }

    $Merged       = [System.Collections.ArrayList]::new()
    foreach ($e in $ExistingList) { $Merged.Add($e) | Out-Null }

    $AddedCount   = 0
    $SkippedCount = 0

    foreach ($Ioc in $NewIocs) {
        if ($ExistingValues.Contains($Ioc.Value)) {
            $SkippedCount++
        } else {
            $Merged.Add([PSCustomObject]@{
                value = $Ioc.Value.ToLower()
                notes = $Ioc.Notes
                type  = $Ioc.Type
            }) | Out-Null
            $ExistingValues.Add($Ioc.Value) | Out-Null
            $AddedCount++
        }
    }

    return [PSCustomObject]@{
        MergedList   = $Merged.ToArray()
        AddedCount   = $AddedCount
        SkippedCount = $SkippedCount
    }
}


# ------------------------------------------------------------------------------
# Function : Set-GlobalPolicyUdso
# Purpose  : Writes the updated UDSO list back to the global policy for one
#            product type.
#
# Uses replace-on-presence semantics: only the userDefinedSuspiciousObjects
# block is sent, so all other policy settings remain unchanged.
#
# Parameters:
#   PolicyKey - "spPolicy" or "splmPolicy"
#   UdsoList  - The complete (merged) array of UDSO objects to store
# ------------------------------------------------------------------------------
function Set-GlobalPolicyUdso {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyKey,

        [Parameter(Mandatory = $true)]
        [array]$UdsoList
    )

    $Body = @{
        policy = @{
            $PolicyKey = @{
                userDefinedSuspiciousObjects = @{
                    list = $UdsoList
                }
            }
        }
    }

    Invoke-StellarAPI -Method "PUT" -Endpoint "/api/v1/policy/global" -Body $Body | Out-Null
}


# ------------------------------------------------------------------------------
# Function : Get-HashType
# Purpose  : Infers the StellarOne UDSO type from the length of a hash string.
#
# Returns  : "TYPE_SHA1", "TYPE_SHA256", "MD5" (unsupported), or $null (invalid).
# ------------------------------------------------------------------------------
function Get-HashType {
    param([string]$Hash)

    $Trimmed = $Hash.Trim()
    if ($Trimmed -notmatch '^[0-9a-fA-F]+$') { return $null }

    switch ($Trimmed.Length) {
        40 { return "TYPE_SHA1"   }
        64 { return "TYPE_SHA256" }
        32 { return "MD5"         }   # Valid hex but unsupported by StellarOne UDSO API
        default { return $null }
    }
}


# ==============================================================================
# SECTION 5 - PARSE THE CSV FILE
# ==============================================================================
# Supported layouts:
#   hash,description           -- 2 columns (action column optional)
#   hash,description,action    -- 3 columns (action logged but not sent to API)
#
# The StellarOne UDSO API does not support a per-hash action (BLOCK/LOG).
# The action is a policy-level setting configured in the StellarOne console.

Write-Host "[STEP 1/3] Reading IOCs from CSV ..." -ForegroundColor Cyan

$IocList     = [System.Collections.ArrayList]::new()
$SkippedMd5  = 0
$SkippedBad  = 0
$LineNo      = 0

foreach ($RawLine in (Get-Content $CsvPath -Encoding UTF8)) {
    $LineNo++
    $Stripped = $RawLine.Trim()

    # Skip blank lines and comment lines.
    if ($Stripped -eq "" -or $Stripped.StartsWith("#")) { continue }

    # Split on comma; handle up to 3 columns.
    $Cols = $Stripped -split ",", 3

    if ($Cols.Count -lt 2) {
        Write-Host "  [WARN] Line ${LineNo}: expected at least 2 columns -- skipping." `
            -ForegroundColor Yellow
        $SkippedBad++
        continue
    }

    $HashVal   = $Cols[0].Trim()
    $DescVal   = $Cols[1].Trim()
    $ActionVal = if ($Cols.Count -ge 3) { $Cols[2].Trim().ToUpper() } else { "BLOCK" }

    # Skip the header row.
    if ($HashVal -ieq "hash") { continue }

    $HashType = Get-HashType -Hash $HashVal

    if ($HashType -eq "MD5") {
        Write-Host "  [SKIP] Line ${LineNo}: MD5 hash not supported by StellarOne UDSO API -- $HashVal" `
            -ForegroundColor Yellow
        $SkippedMd5++
        continue
    }

    if ($null -eq $HashType) {
        Write-Host "  [SKIP] Line ${LineNo}: '$HashVal' -- not a recognised SHA-1 or SHA-256 hash." `
            -ForegroundColor Yellow
        $SkippedBad++
        continue
    }

    $IocList.Add([PSCustomObject]@{
        LineNo = $LineNo
        Value  = $HashVal.ToLower()
        Notes  = $DescVal
        Action = $ActionVal   # Stored for display only; not sent to the API.
        Type   = $HashType
    }) | Out-Null
}

Write-Host "  [INFO] $($IocList.Count) valid IOC(s) ready to import." -ForegroundColor DarkGray
if ($SkippedMd5  -gt 0) {
    Write-Host "  [INFO] $SkippedMd5 MD5 hash(es) skipped -- not supported by StellarOne UDSO API." `
        -ForegroundColor Yellow
}
if ($SkippedBad -gt 0) {
    Write-Host "  [INFO] $SkippedBad row(s) skipped due to format errors." -ForegroundColor Yellow
}
Write-Host ""

if ($IocList.Count -eq 0) {
    Write-Warning "Nothing to import.  Verify that the CSV contains SHA-1 or SHA-256 hashes."
    exit 0
}


# ==============================================================================
# SECTION 6 - MAIN WORKFLOW: MERGE IOCS INTO EACH PRODUCT POLICY
# ==============================================================================
# StellarOne stores UDSOs inside the global policy, once per product type.
# We update both StellarProtect (spPolicy) and StellarProtect Legacy Mode
# (splmPolicy) so that agents of both types receive the new hashes.

$Products = @(
    [PSCustomObject]@{ Code = "PRODUCT_SP";   Key = "spPolicy";   Label = "StellarProtect" },
    [PSCustomObject]@{ Code = "PRODUCT_SPLM"; Key = "splmPolicy"; Label = "StellarProtect Legacy Mode" }
)

$TotalAdded  = 0
$TotalDupes  = 0
$TotalFailed = 0

Write-Host "[STEP 2/3] Merging $($IocList.Count) IOC(s) into global policy ..." -ForegroundColor Cyan
Write-Host ""

foreach ($Product in $Products) {
    Write-Host "  --- $($Product.Label) ($($Product.Code)) ---" -ForegroundColor White

    # GET current policy
    Write-Host "  [API] Reading current policy ..." -ForegroundColor DarkGray
    try {
        $PolicyResp = Get-GlobalPolicy -ProductCode $Product.Code
    } catch {
        Write-Host "  [FAIL] Could not read policy: $_" -ForegroundColor Red
        $TotalFailed += $IocList.Count
        continue
    }

    if ($null -eq $PolicyResp) {
        Write-Host "  [SKIP] No global policy found for $($Product.Label) -- skipping." `
            -ForegroundColor Yellow
        continue
    }

    $Existing = Get-UdsoList -PolicyResponse $PolicyResp -PolicyKey $Product.Key
    Write-Host "  [INFO] Existing UDSOs in policy: $($Existing.Count)" -ForegroundColor DarkGray

    # Merge new hashes into the existing list.
    $MergeResult = Merge-Iocs -ExistingList $Existing -NewIocs $IocList.ToArray()
    Write-Host "  [INFO] New entries to add: $($MergeResult.AddedCount)  |  Already present (skipped): $($MergeResult.SkippedCount)" `
        -ForegroundColor DarkGray

    if ($MergeResult.AddedCount -eq 0) {
        Write-Host "  [INFO] All hashes already exist in the policy -- no update needed." `
            -ForegroundColor DarkGray
        $TotalDupes += $MergeResult.SkippedCount
        Write-Host ""
        continue
    }

    # PUT updated policy
    $TotalEntries = $MergeResult.MergedList.Count
    Write-Host "  [API] Writing updated policy ($TotalEntries total UDSOs) ..." -ForegroundColor DarkGray
    try {
        Set-GlobalPolicyUdso -PolicyKey $Product.Key -UdsoList $MergeResult.MergedList
        Write-Host "  [OK]  Policy updated successfully." -ForegroundColor Green
        $TotalAdded  += $MergeResult.AddedCount
        $TotalDupes  += $MergeResult.SkippedCount
    } catch {
        Write-Host "  [FAIL] Could not write policy: $_" -ForegroundColor Red
        $TotalFailed += $MergeResult.AddedCount
    }

    Write-Host ""
}


# ==============================================================================
# SECTION 7 - SUMMARY
# ==============================================================================

$SummaryColor = if ($TotalFailed -eq 0) { "Green" } else { "Yellow" }

Write-Host ""
Write-Host "==============================================================" -ForegroundColor $SummaryColor
Write-Host "  Import Summary" -ForegroundColor White
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  CSV file         : $CsvPath"
Write-Host "  IOCs in CSV      : $($IocList.Count)"
Write-Host "  Added            : $TotalAdded" -ForegroundColor Green
if ($TotalDupes   -gt 0) { Write-Host "  Already present  : $TotalDupes"  -ForegroundColor DarkGray }
if ($SkippedMd5   -gt 0) { Write-Host "  Skipped (MD5)    : $SkippedMd5"  -ForegroundColor Yellow }
if ($SkippedBad   -gt 0) { Write-Host "  Skipped (invalid): $SkippedBad"  -ForegroundColor Yellow }
if ($TotalFailed  -gt 0) { Write-Host "  Failed           : $TotalFailed" -ForegroundColor Red    }
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  NOTE: BLOCK/LOG action is a policy-level setting in the"
Write-Host "  StellarOne console, not configurable per individual hash."
Write-Host "==============================================================" -ForegroundColor $SummaryColor
Write-Host ""

if ($TotalFailed -gt 0) {
    exit 1
}
