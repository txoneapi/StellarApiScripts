#Requires -Version 5.1
# ==============================================================================
# FILE      : Stellar_ExportAgents.ps1
# CREATED   : 2026-03-14
# PURPOSE   : Exports all agents from StellarOne to a CSV file that reflects
#             the full group tree structure, with one column per hierarchy level.
# ==============================================================================

<#
.SYNOPSIS
    Exports every managed agent from StellarOne to a CSV file.

.DESCRIPTION
    This script connects to a TXOne StellarOne management server, downloads
    every managed agent and every agent group, and writes a CSV file where each
    row is one agent and the columns describe its position in the group tree.

    CSV column layout:
      Hostname    - The agent's hostname (computer name).
      IP          - The agent's IP address as reported by StellarOne.
      Online      - "Yes" if the agent is currently connected, "No" otherwise.
      DirectGroup - The name of the group the agent belongs to directly
                    (always the leaf/innermost group).  Repeated here in a
                    fixed column so it is easy to sort or filter without
                    knowing how deep the tree goes.
      All         - L1: always the root group, named "All" in StellarOne.
      L2 .. Ln    - One column per additional level of nesting.  The depth
                    matches the deepest agent in the export; shallower agents
                    leave trailing columns blank.
      FullPath    - The complete group path as a human-readable string,
                    e.g. "All > SiteA > Production > Line-1".

    API endpoints used:
      GET /api/v1/groups?limit=100&page=N&pageToken=T  - List all groups
      GET /api/v1/agents?limit=100&page=N&pageToken=T  - List all agents

.PARAMETER OutputFile
    Optional.  Full path (or filename) for the output CSV file.
    Default: StellarOne_Agents_YYYYMMDD_HHMMSS.csv in the same folder as
    this script.

.EXAMPLE
    .\Stellar_ExportAgents.ps1

    Exports all agents to a timestamped CSV file in the script directory.

.EXAMPLE
    .\Stellar_ExportAgents.ps1 -OutputFile "C:\Reports\agents.csv"

    Exports all agents to a specific file path.

.NOTES
    Prerequisites:
      - PowerShell 5.1 or later (built into Windows 10 / Server 2016+)
      - StellarOne.conf  must be in the same folder as this script
      - Network access to the StellarOne management server
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               HelpMessage = "Output CSV file path. Default: auto-generated timestamped file.")]
    [string]$OutputFile = ""
)

$ErrorActionPreference = "Stop"


# ==============================================================================
# SECTION 1 - READ CONFIGURATION FILE
# ==============================================================================
# Rather than hard-coding the server address and API key directly in this
# script (which would be a security risk if the script is shared), we read
# them from a single configuration file that lives alongside the script.
#
#   StellarOne.conf  ->  contains both the server URL and the API key
# ==============================================================================

# $ScriptDir resolves to the folder where this .ps1 file is saved.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Resolve the output file path.
# If not provided, generate a timestamped filename in the script directory.
if ($OutputFile -eq "") {
    $Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = Join-Path $ScriptDir "StellarOne_Agents_$Timestamp.csv"
}

$ConfPath = Join-Path $ScriptDir "StellarOne.conf"

# Verify the configuration file exists before proceeding.
if (-not (Test-Path $ConfPath)) {
    Write-Error ("Required configuration file not found: $ConfPath`n" +
                 "Please copy stellarOne_example.conf to StellarOne.conf and fill in your values.")
    exit 1
}

# Parse StellarOne.conf  -- expected format:
#   StellarOneURL="https://x.x.x.x"
#   ApiKey="<long hex string>"
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

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  StellarOne - Export Agents" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  Server           : $BaseUrl"
Write-Host "  API key (first 8): $KeyPreview..."
Write-Host "  Output file      : $OutputFile"
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""


# ==============================================================================
# SECTION 2 - TRUST THE SERVER'S SSL/TLS CERTIFICATE
# ==============================================================================
# StellarOne ships with a self-signed TLS certificate.  By default, PowerShell
# refuses to connect to servers whose certificate was not issued by a trusted
# Certificate Authority (CA) -- just like a browser shows a warning for unknown
# HTTPS sites.
#
# The code below temporarily tells PowerShell to trust all certificates for the
# rest of this session.  This is acceptable on a private management network but
# should NOT be used in security-sensitive or internet-facing environments.
# ==============================================================================

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

# Enable TLS 1.2 -- required by most modern HTTPS servers.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12


# ==============================================================================
# SECTION 3 - DEFINE THE COMMON REQUEST HEADERS
# ==============================================================================
# Every HTTP request sent to StellarOne must carry an Authorization header
# containing the API key.  Think of it like a keycard: you must present it
# each time you enter a restricted area.
#
# The Content-Type and Accept headers tell the server that we are sending and
# expecting data in JSON format (a lightweight text-based data format).
# ==============================================================================

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
# Why have one shared function?
#   Using a single wrapper ensures that every API call uses the same server URL,
#   headers, and error-handling logic.  If something needs to change (e.g.,
#   adding a new header), you only change it in one place.
#
# Parameters:
#   Method   - The HTTP method: "GET" (read), "POST" (create), "PUT" (update)
#   Endpoint - The URL path to call, e.g. "/api/v1/agents"
#   Body     - Optional hashtable that becomes the JSON request body
# ------------------------------------------------------------------------------
function Invoke-StellarAPI {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET","POST","PUT","DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [hashtable]$Body = $null
    )

    $Url = "$BaseUrl$Endpoint"
    Write-Verbose "    --> $Method $Url"

    $Params = @{
        Method      = $Method
        Uri         = $Url
        Headers     = $Headers
        ContentType = "application/json"
        ErrorAction = "Stop"
    }

    if ($null -ne $Body) {
        # ConvertTo-Json converts the PowerShell hashtable to a JSON string.
        # -Depth 20 ensures deeply nested objects are fully serialized.
        $Params["Body"] = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    try {
        # Invoke-RestMethod sends the HTTP request and automatically parses
        # the JSON response into a PowerShell object.
        $Response = Invoke-RestMethod @Params
        return $Response
    }
    catch {
        # Extract the HTTP status code (e.g. 404 = Not Found, 401 = Unauthorized)
        $StatusCode = 0
        if ($null -ne $_.Exception.Response) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }

        # Try to extract a human-readable message from the error response body.
        $ErrorDetail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $Parsed = $_.ErrorDetails.Message | ConvertFrom-Json
                $ErrorDetail = $Parsed | ConvertTo-Json -Depth 3
            } catch { }
        }

        Write-Error "API call failed: $Method $Endpoint  |  HTTP $StatusCode  |  $ErrorDetail"
        throw
    }
}


# ------------------------------------------------------------------------------
# Function : Get-AllGroups
# Purpose  : Returns a complete list of every agent group in StellarOne.
#
# Why is pagination needed?
#   StellarOne returns results in "pages" -- like a book -- instead of sending
#   thousands of records at once.  Each page contains up to $PageSize groups.
#   At the end of each page, the API provides a "page token" (like a bookmark)
#   that lets us request the next page.  We keep requesting pages until the
#   API stops providing a token, meaning we have reached the last page.
#
# Returns  : An array of group objects.
# ------------------------------------------------------------------------------
function Get-AllGroups {
    $AllGroups  = [System.Collections.ArrayList]::new()
    $PageToken  = $null
    $PageNumber = 1
    $PageSize   = 100   # Request 100 groups per page (API maximum)

    do {
        Write-Host "  [API] Fetching group list - page $PageNumber ..." -ForegroundColor DarkGray

        # Build the query string.  The API requires page >= 1, so we always
        # include it.  On subsequent pages we also send the pageToken returned
        # by the previous response (acts as a bookmark for the next page).
        $QueryString = "?limit=$PageSize&page=$PageNumber"
        if ($null -ne $PageToken -and $PageToken -ne "") {
            $Encoded      = [System.Uri]::EscapeDataString($PageToken)
            $QueryString += "&pageToken=$Encoded"
        }

        $Response = Invoke-StellarAPI -Method "GET" -Endpoint "/api/v1/groups$QueryString"

        if ($Response.groups) {
            $AllGroups.AddRange($Response.groups) | Out-Null
        }

        # Move to the next page if the API provided a token; otherwise we are done.
        $PageToken = $null
        if ($Response.pagination -and
            $null -ne $Response.pagination.pageToken -and
            $Response.pagination.pageToken -ne "") {
            $PageToken = $Response.pagination.pageToken
        }

        $PageNumber++

    } while ($null -ne $PageToken -and $PageToken -ne "")

    $TotalFound = $AllGroups.Count
    Write-Host "  [INFO] Found $TotalFound group(s) in StellarOne." -ForegroundColor DarkGray

    return ,$AllGroups.ToArray()
}


# ------------------------------------------------------------------------------
# Function : Get-AllAgents
# Purpose  : Returns a complete list of every managed agent in StellarOne.
#
# Uses the same pagination technique as Get-AllGroups:
#   - Request up to 100 agents per page.
#   - Follow the pageToken until the API returns no more pages.
#
# Returns  : An array of agent objects, each with:
#              hostname          - the computer/device hostname
#              ipAddress         - the agent's IP address
#              agentOnlineStatus - boolean: true if currently online
#              groupUuid         - UUID of the group this agent belongs to
#              agentUuid         - unique identifier for the agent
# ------------------------------------------------------------------------------
function Get-AllAgents {
    $AllAgents  = [System.Collections.ArrayList]::new()
    $PageToken  = $null
    $PageNumber = 1
    $PageSize   = 100

    do {
        Write-Host "  [API] Fetching agent list - page $PageNumber ..." -ForegroundColor DarkGray

        $QueryString = "?limit=$PageSize&page=$PageNumber"
        if ($null -ne $PageToken -and $PageToken -ne "") {
            $Encoded      = [System.Uri]::EscapeDataString($PageToken)
            $QueryString += "&pageToken=$Encoded"
        }

        $Response = Invoke-StellarAPI -Method "GET" -Endpoint "/api/v1/agents$QueryString"

        if ($Response.agents) {
            $AllAgents.AddRange($Response.agents) | Out-Null
        }

        $PageToken = $null
        if ($Response.pagination -and
            $null -ne $Response.pagination.pageToken -and
            $Response.pagination.pageToken -ne "") {
            $PageToken = $Response.pagination.pageToken
        }

        $PageNumber++

    } while ($null -ne $PageToken -and $PageToken -ne "")

    $TotalFound = $AllAgents.Count
    Write-Host "  [INFO] Found $TotalFound agent(s) in StellarOne." -ForegroundColor DarkGray

    return ,$AllAgents.ToArray()
}


# ------------------------------------------------------------------------------
# Function : Resolve-GroupPath
# Purpose  : Walks the group tree upward from the given group UUID to the root,
#            collecting group names, then reverses the list so the path reads
#            from root (All) down to the direct group.
#
# Example:
#   Given tree:   All > SiteA > Production > Line-1
#   Starting at Line-1's UUID, this function returns:
#     @("All", "SiteA", "Production", "Line-1")
#
# Safety:
#   A $Visited hashtable prevents infinite loops in case the API returns a
#   malformed tree with a circular parent reference.
#
# Parameters:
#   GroupUuid  - UUID of the agent's direct group
#   GroupMap   - Hashtable { uuid -> group_object } for fast lookup
#
# Returns  : An ordered array of group name strings, root first.
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# Function : Format-Timestamp
# Purpose  : Converts a Unix timestamp (int or numeric string) returned by the
#            StellarOne API into a readable UTC date string.
#
# StellarOne uses int64 for all timestamps; the REST layer may return them as
# a plain integer or as a quoted string.  Both are handled here.
# Returns an empty string for zero, null, or unparseable values.
# ------------------------------------------------------------------------------
function Format-Timestamp {
    param($Val)
    if (-not $Val -or "$Val" -eq "" -or "$Val" -eq "0") { return "" }
    try {
        $ts = [long]"$Val"
        if ($ts -eq 0) { return "" }
        return [System.DateTimeOffset]::FromUnixTimeSeconds($ts).UtcDateTime.ToString("yyyy-MM-dd HH:mm UTC")
    } catch { return "" }
}


# ------------------------------------------------------------------------------
# Function : Get-AgentProp
# Purpose  : Safely retrieves a property value from an agent PSCustomObject.
#            Returns $Default if the property does not exist or is null.
# ------------------------------------------------------------------------------
function Get-AgentProp {
    param($Obj, [string]$Name, $Default = "")
    if ($Obj.PSObject.Properties[$Name] -and $null -ne $Obj.$Name) {
        return "$($Obj.$Name)"
    }
    return $Default
}


function Resolve-GroupPath {
    param(
        [string]$GroupUuid,
        [hashtable]$GroupMap
    )

    if (-not $GroupMap.ContainsKey($GroupUuid)) {
        return @("(unknown)")
    }

    $Path        = [System.Collections.ArrayList]::new()
    $Visited     = @{}
    $CurrentUuid = $GroupUuid

    while ($CurrentUuid -and -not $Visited.ContainsKey($CurrentUuid)) {
        $Visited[$CurrentUuid] = $true
        $Group = $GroupMap[$CurrentUuid]
        if ($null -eq $Group) { break }

        $Path.Add($Group.name) | Out-Null

        $CurrentUuid = ""
        if ($Group.PSObject.Properties["parentGroupUuid"] -and
            $null -ne $Group.parentGroupUuid -and
            $Group.parentGroupUuid -ne "") {
            $CurrentUuid = $Group.parentGroupUuid
        }
    }

    # $Path is currently [leaf, ..., root]; reverse to get [root, ..., leaf].
    $PathArray = $Path.ToArray()
    [Array]::Reverse($PathArray)
    return $PathArray
}


# ==============================================================================
# SECTION 5 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
# We need the full group tree so we can resolve each agent's ancestry.
# Groups are identified by UUID in the agent records; we need names and parents.
Write-Host "[STEP 1/4] Retrieving all agent groups from StellarOne ..." -ForegroundColor Cyan

$AllGroups = Get-AllGroups

Write-Host ""


# -- STEP 2: Load the complete agent list --------------------------------------
Write-Host "[STEP 2/4] Retrieving all agents from StellarOne ..." -ForegroundColor Cyan

$AllAgents = Get-AllAgents

Write-Host ""


# -- STEP 3: Build the group lookup map and resolve every agent's path --------
Write-Host "[STEP 3/4] Resolving group hierarchy for each agent ..." -ForegroundColor Cyan

# Build a fast UUID-keyed hashtable from the flat group list.
# This gives O(1) lookup when walking the tree for each agent.
$GroupMap = @{}
foreach ($Group in $AllGroups) {
    if ($Group.groupUuid) {
        $GroupMap[$Group.groupUuid] = $Group
    }
}

# For each agent, resolve its full path and store the result.
$ResolvedAgents = [System.Collections.ArrayList]::new()
$MaxDepth       = 1

foreach ($Agent in $AllAgents) {
    $GroupUuid = if ($Agent.PSObject.Properties["groupUuid"]) { $Agent.groupUuid } else { "" }

    $Path = Resolve-GroupPath -GroupUuid $GroupUuid -GroupMap $GroupMap

    # DirectGroup is the last (innermost) element of the resolved path.
    # It is also the deepest "L" column, but we duplicate it in a fixed-position
    # column at the front so it is always easy to find in the CSV regardless of
    # how many L columns there are.
    $DirectGroup = if ($Path.Count -gt 0) { $Path[-1] } else { "(unknown)" }

    # Build a human-readable full path string for the last column.
    $FullPath = $Path -join " > "

    # agentOnlineStatus is a boolean from the API.
    # Convert to "Yes" / "No" for readability in Excel/CSV viewers.
    $OnlineRaw = $false
    if ($Agent.PSObject.Properties["agentOnlineStatus"]) {
        $OnlineRaw = $Agent.agentOnlineStatus
    }
    $OnlineStr = if ($OnlineRaw) { "Yes" } else { "No" }

    $ResolvedAgents.Add([PSCustomObject]@{
        # Fixed identity columns
        Hostname    = Get-AgentProp $Agent "hostname"
        IP          = Get-AgentProp $Agent "ipAddress"
        Online      = $OnlineStr
        DirectGroup = $DirectGroup
        # Identity / Inventory
        MACAddress  = Get-AgentProp $Agent "macAddress"
        OS          = Get-AgentProp $Agent "os"
        Vendor      = Get-AgentProp $Agent "vendor"
        Model       = Get-AgentProp $Agent "model"
        Location    = Get-AgentProp $Agent "location"
        Description = Get-AgentProp $Agent "description"
        Product     = Get-AgentProp $Agent "productCode"
        Version     = Get-AgentProp $Agent "productVersion"
        # Status / Health
        SyncStatus      = Get-AgentProp $Agent "syncStatus"
        RealtimeScan    = Get-AgentProp $Agent "realtimeScanStatus"
        Lockdown        = Get-AgentProp $Agent "lockdownStatus"
        Maintenance     = Get-AgentProp $Agent "maintenanceStatus"
        ComponentStatus = Get-AgentProp $Agent "componentStatus"
        RebootRequired  = if ($Agent.PSObject.Properties["rebootRequired"] -and $Agent.rebootRequired) { "Yes" } else { "No" }
        TimeGap         = Get-AgentProp $Agent "timeGap"
        # License
        LicenseStatus = Get-AgentProp $Agent "licenseStatus"
        LicenseType   = Get-AgentProp $Agent "licenseType"
        LicenseExpiry = Format-Timestamp (Get-AgentProp $Agent "licenseExpiredAt")
        # Security features
        ApprovedListState    = Get-AgentProp $Agent "approvedListState"
        ApprovedListCount    = Get-AgentProp $Agent "approvedListCount"
        ApprovedListProgress = Get-AgentProp $Agent "approvedListProgress"
        OBADMode             = Get-AgentProp $Agent "obadMode"
        OBADProgress         = Get-AgentProp $Agent "obadProgress"
        DeviceControl        = Get-AgentProp $Agent "deviceControlStatus"
        # Timestamps
        LastConnected       = Format-Timestamp (Get-AgentProp $Agent "connectedAt")
        LastUpgraded        = Format-Timestamp (Get-AgentProp $Agent "upgradedAt")
        LastComponentUpdate = Format-Timestamp (Get-AgentProp $Agent "lastComponentUpdatedAt")
        RegisteredAt        = Format-Timestamp (Get-AgentProp $Agent "createdAt")
        # Tree (computed above)
        Path        = $Path
        FullPath    = $FullPath
    }) | Out-Null

    # Track the maximum path depth to know how many "L" columns we need.
    if ($Path.Count -gt $MaxDepth) {
        $MaxDepth = $Path.Count
    }
}

Write-Host "  [INFO] Maximum group nesting depth: $MaxDepth" -ForegroundColor DarkGray
Write-Host ""


# -- STEP 4: Write the CSV file ------------------------------------------------
Write-Host "[STEP 4/4] Writing CSV file: $OutputFile" -ForegroundColor Cyan

# Build the dynamic tree column header list.
#   "All"        -> L1, the root group (always the same value: "All")
#   "L2" .. "Ln" -> one column per additional nesting level
#
# Why name the first tree column "All" instead of "L1"?
#   In StellarOne the root group is always named "All".  Using "All" as the
#   column header makes it immediately obvious what it represents and serves
#   as a visual anchor when the file is opened in Excel.
if ($MaxDepth -ge 1) {
    $TreeHeaders = @("All")
} else {
    $TreeHeaders = @()
}
for ($i = 2; $i -le $MaxDepth; $i++) {
    $TreeHeaders += "L$i"
}

# Build each output row as an ordered hashtable so the CSV columns appear
# in exactly the order we define them (PSCustomObject column order is not
# guaranteed in PowerShell 5.1 without [ordered]).
$AllRows = [System.Collections.ArrayList]::new()

foreach ($Agent in $ResolvedAgents) {
    $Row = [ordered]@{}

    # Fixed identity columns.
    $Row["Hostname"]    = $Agent.Hostname
    $Row["IP"]          = $Agent.IP
    $Row["Online"]      = $Agent.Online
    $Row["DirectGroup"] = $Agent.DirectGroup

    # Detail columns (all agent fields, in order).
    $Row["MAC Address"]             = $Agent.MACAddress
    $Row["OS"]                      = $Agent.OS
    $Row["Vendor"]                  = $Agent.Vendor
    $Row["Model"]                   = $Agent.Model
    $Row["Location"]                = $Agent.Location
    $Row["Description"]             = $Agent.Description
    $Row["Product"]                 = $Agent.Product
    $Row["Version"]                 = $Agent.Version
    $Row["Sync Status"]             = $Agent.SyncStatus
    $Row["Realtime Scan"]           = $Agent.RealtimeScan
    $Row["Lockdown"]                = $Agent.Lockdown
    $Row["Maintenance"]             = $Agent.Maintenance
    $Row["Component Status"]        = $Agent.ComponentStatus
    $Row["Reboot Required"]         = $Agent.RebootRequired
    $Row["Time Gap (s)"]            = if ($Agent.TimeGap) { $Agent.TimeGap } else { "" }
    $Row["License Status"]          = $Agent.LicenseStatus
    $Row["License Type"]            = $Agent.LicenseType
    $Row["License Expiry"]          = $Agent.LicenseExpiry
    $Row["Approved List State"]     = $Agent.ApprovedListState
    $Row["Approved List Count"]     = $Agent.ApprovedListCount
    $Row["Approved List Progress %"] = $Agent.ApprovedListProgress
    $Row["OBAD Mode"]               = $Agent.OBADMode
    $Row["OBAD Progress %"]         = $Agent.OBADProgress
    $Row["Device Control"]          = $Agent.DeviceControl
    $Row["Last Connected"]          = $Agent.LastConnected
    $Row["Last Upgraded"]           = $Agent.LastUpgraded
    $Row["Last Component Update"]   = $Agent.LastComponentUpdate
    $Row["Registered At"]           = $Agent.RegisteredAt

    # Tree columns: path[0] → "All", path[1] → "L2", etc.
    # Shorter paths leave trailing columns empty.
    for ($i = 0; $i -lt $TreeHeaders.Count; $i++) {
        $Header     = $TreeHeaders[$i]
        $Row[$Header] = if ($i -lt $Agent.Path.Count) { $Agent.Path[$i] } else { "" }
    }

    # Full path string last.
    $Row["FullPath"] = $Agent.FullPath

    $AllRows.Add([PSCustomObject]$Row) | Out-Null
}

try {
    # Export-Csv with -NoTypeInformation omits the PowerShell type header line
    # that would otherwise appear as the first row of the file.
    # -Encoding UTF8 ensures special characters in hostnames are preserved.
    # Note: PowerShell 5.1's Export-Csv -Encoding UTF8 does NOT write a BOM.
    # If you need Excel to auto-detect UTF-8, open via Data > From Text/CSV
    # and select UTF-8 encoding, or use the Python or Bash version which
    # writes a UTF-8 BOM automatically.
    $AllRows.ToArray() | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    $ExportedCount = $AllRows.Count
    Write-Host "  [OK]  CSV written: $ExportedCount agent(s) exported." -ForegroundColor Green
}
catch {
    Write-Error "Could not write output file '$OutputFile': $_"
    exit 1
}


# ==============================================================================
# SECTION 6 - SUMMARY
# ==============================================================================

$OnlineCount  = @($ResolvedAgents | Where-Object { $_.Online -eq "Yes" }).Count
$OfflineCount = $ResolvedAgents.Count - $OnlineCount
$ColCount     = 4 + 28 + $TreeHeaders.Count + 1   # fixed + detail + tree + FullPath

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  Agent Export Summary" -ForegroundColor White
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Total agents exported : $($ResolvedAgents.Count)"
Write-Host "  Online                : $OnlineCount" -ForegroundColor Green
Write-Host "  Offline               : $OfflineCount"
Write-Host "  Max group depth       : $MaxDepth"
Write-Host "  CSV columns           : $ColCount"
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Output file           : $OutputFile"
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""
