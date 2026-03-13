#Requires -Version 5.1
# ==============================================================================
# FILE      : Stellar_CopyGroupPolicy.ps1
# CREATED   : 2026-03-13 00:00:00
# PURPOSE   : Copies the security policy from one StellarOne agent group to
#             another, creating the destination group if it does not yet exist.
# ==============================================================================

<#
.SYNOPSIS
    Copies the security policy from a StellarOne source agent group to a
    destination agent group.

.DESCRIPTION
    This script automates a common administrative task in TXOne StellarOne:
    taking the security configuration (policy) that is already set up on one
    group of managed agents and applying it to another group.

    What the script does, step by step:
      1. Reads the StellarOne server address and API key from configuration files.
      2. Connects to StellarOne and downloads the complete list of agent groups.
      3. Verifies that the Source group exists.
      4. Checks whether the Destination group exists; creates it if it does not.
      5. Retrieves the security policy from the Source group for every product
         type it contains (StellarProtect, StellarProtect Legacy Mode, or Linux).
      6. Applies each retrieved policy to the Destination group.

    API endpoints used:
      GET  /api/v1/groups                                 - List all groups
      POST /api/v1/groups                                 - Create a new group
      GET  /api/v1/policy/groups/{uuid}/product/{code}   - Read a group policy
      PUT  /api/v1/policy/groups/{uuid}                  - Write a group policy

.PARAMETER SourceAgentGroup
    The exact name of the agent group whose policy you want to copy FROM.
    Case-sensitive - must match the group name shown in the StellarOne console.

.PARAMETER DestinationAgentGroup
    The exact name of the agent group to copy the policy TO.
    If this group does not exist in StellarOne it will be created automatically.

.EXAMPLE
    .\Stellar_CopyGroupPolicy.ps1 -SourceAgentGroup "Production-Line-A" `
                                  -DestinationAgentGroup "Production-Line-B"

    Copies all policies from "Production-Line-A" to "Production-Line-B".
    If "Production-Line-B" does not exist it is created first.

.NOTES
    Prerequisites:
      - PowerShell 5.1 or later (built into Windows 10 / Server 2016+)
      - StellarOne.conf  must be in the same folder as this script
      - Network access to the StellarOne management server
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
               HelpMessage = "Name of the source group to copy the policy FROM.")]
    [string]$SourceAgentGroup,

    [Parameter(Mandatory = $true,
               HelpMessage = "Name of the destination group to copy the policy TO.")]
    [string]$DestinationAgentGroup
)

$ErrorActionPreference = "Stop"


# ==============================================================================
# SECTION 1 - READ CONFIGURATION FILES
# ==============================================================================
# Rather than hard-coding the server address and API key directly in this
# script (which would be a security risk if the script is shared), we read
# them from two separate files that live alongside the script.
#
#   StellarOne.conf  ->  contains the URL of the StellarOne management server
#   secrets.txt      ->  contains the API key used to authenticate every request
# ==============================================================================

# $ScriptDir resolves to the folder where this .ps1 file is saved.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

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
Write-Host "  StellarOne - Copy Group Policy" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  Server           : $BaseUrl"
Write-Host "  API key (first 8): $KeyPreview..."
Write-Host "  Source group     : $SourceAgentGroup"
Write-Host "  Destination group: $DestinationAgentGroup"
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
#   Endpoint - The URL path to call, e.g. "/api/v1/groups"
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
        # -Depth 20 ensures deeply nested objects (like policy rules) are fully
        # serialized and not truncated.
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
# Function : Find-GroupByName
# Purpose  : Searches a list of group objects for one whose "name" property
#            exactly matches the requested name.
# Returns  : The matching group object, or $null if no match is found.
# ------------------------------------------------------------------------------
function Find-GroupByName {
    param(
        [array]$Groups,
        [string]$Name
    )

    # Iterate through all groups and return the first name match.
    # Using foreach instead of a pipeline avoids potential PS 5.1 pipeline
    # stopping issues when combined with Stop error action preference.
    foreach ($Group in $Groups) {
        if ($Group.name -eq $Name) {
            return $Group
        }
    }
    return $null
}


# ------------------------------------------------------------------------------
# Function : New-StellarGroup
# Purpose  : Creates a brand-new agent group in StellarOne under a given parent.
#            The API requires parentGroupUuid -- all groups must have a parent.
#            We use the source group's parent so the new group is created as a
#            sibling of the source group (same level in the hierarchy).
# Returns  : The newly created group object, which includes its UUID.
# ------------------------------------------------------------------------------
function New-StellarGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ParentGroupUuid
    )

    Write-Host "  [API] Creating new group '$Name' under parent UUID $ParentGroupUuid ..." `
        -ForegroundColor Yellow

    # Both name and parentGroupUuid are required by the API.
    $Body     = @{ name = $Name; parentGroupUuid = $ParentGroupUuid }
    $Response = Invoke-StellarAPI -Method "POST" -Endpoint "/api/v1/groups" -Body $Body

    $NewUuid = $Response.group.groupUuid
    Write-Host "  [OK]  Group '$Name' created  |  UUID = $NewUuid" -ForegroundColor Green

    return $Response.group
}


# ------------------------------------------------------------------------------
# Function : Get-GroupPolicy
# Purpose  : Retrieves the security policy for a group and a specific product.
#
# Why specify a product?
#   A single StellarOne group can contain agents running different TXOne products:
#     PRODUCT_SP    - StellarProtect (modern Windows agent)
#     PRODUCT_SPLM  - StellarProtect Legacy Mode (older Windows agent)
#     PRODUCT_LINUX - StellarProtect for Linux
#   Each product has its own independent policy configuration, so you must
#   specify which product's policy you want to retrieve.
#
# Parameters:
#   GroupUuid   - The UUID of the group (e.g. "a1b2c3d4-1234-...")
#   ProductCode - One of: "PRODUCT_SP", "PRODUCT_SPLM", "PRODUCT_LINUX"
#
# Returns  : The policy response object, or $null if no policy exists for
#            that product in this group (which is a normal, expected case).
# ------------------------------------------------------------------------------
function Get-GroupPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,

        [Parameter(Mandatory = $true)]
        [string]$ProductCode
    )

    try {
        $Response = Invoke-StellarAPI -Method "GET" `
            -Endpoint "/api/v1/policy/groups/$GroupUuid/product/$ProductCode"
        return $Response
    }
    catch {
        # HTTP 404 (Not Found) simply means this group has no policy configured
        # for this particular product.  This is perfectly normal and expected.
        $StatusCode = 0
        if ($null -ne $_.Exception.Response) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($StatusCode -eq 404) {
            Write-Verbose "    No $ProductCode policy on group $GroupUuid (HTTP 404 - normal)."
            return $null
        }
        throw   # Re-throw any other unexpected error.
    }
}


# ------------------------------------------------------------------------------
# Function : Set-GroupPolicy
# Purpose  : Applies (writes) a security policy to a destination group.
#
# How the update works (replace-on-presence semantics):
#   The StellarOne API uses a smart update strategy:
#   - If you send a policy block (e.g. spPolicy), the server REPLACES that
#     block on the destination group.
#   - If you do NOT send a block, the server leaves it unchanged.
#   This means we can safely update one product's policy without disturbing
#   the policies for other products in the same group.
#
# Parameters:
#   GroupUuid - UUID of the destination group to update.
#   Policy    - The policy object returned by Get-GroupPolicy.
# ------------------------------------------------------------------------------
function Set-GroupPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,

        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    # The API expects the policy wrapped in a "policy" key:
    #   { "policy": { "spPolicy": { ... } } }
    $Body = @{ policy = $Policy }
    Invoke-StellarAPI -Method "PUT" -Endpoint "/api/v1/policy/groups/$GroupUuid" -Body $Body | Out-Null
}


# ------------------------------------------------------------------------------
# Function : Set-GroupPolicyInheritance
# Purpose  : Switches a group between inherited and customised policy mode.
#
# Why is this needed?
#   When a new group is created in StellarOne it defaults to
#   POLICY_INHERITANCE_INHERITED, meaning it simply copies its parent's policy
#   and cannot have its own independent policy.  Before we can write a custom
#   policy to the destination group we must switch it to
#   POLICY_INHERITANCE_CUSTOMIZED.  This call is safe to repeat -- if the group
#   is already in customised mode the API will simply leave it unchanged.
#
# Parameters:
#   GroupUuid - UUID of the group to update.
#   Mode      - "POLICY_INHERITANCE_CUSTOMIZED" or "POLICY_INHERITANCE_INHERITED"
# ------------------------------------------------------------------------------
function Set-GroupPolicyInheritance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupUuid,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    $Body = @{ policyInheritance = $Mode }
    Invoke-StellarAPI -Method "PUT" -Endpoint "/api/v1/groups/$GroupUuid" -Body $Body | Out-Null
}


# ------------------------------------------------------------------------------
# Function : Remove-PasswordFields
# Purpose  : Strips the "passwords" sub-object from a retrieved policy before
#            re-applying it to a different group.
#
# Why is this needed?
#   When you GET a policy from StellarOne, the password fields are returned as
#   empty strings (the server never sends actual password values over the API
#   for security reasons).  If you then PUT those empty strings back, the API
#   rejects them because passwords must be at least 8 characters long.
#
#   The solution: remove the passwords block entirely before sending.  Because
#   the UpdateGroupPolicy endpoint uses replace-on-presence semantics, omitting
#   the passwords block means the destination group keeps whatever password it
#   already has (or the system default for a brand-new group).
#
# Parameters:
#   Policy - The policy PSCustomObject returned by Get-GroupPolicy.
# Returns  : The same object with the passwords property removed (if present).
# ------------------------------------------------------------------------------
function Remove-PasswordFields {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    # Each product policy type may contain a "passwords" sub-object.
    foreach ($PolicyType in @('spPolicy', 'splmPolicy', 'linuxPolicy')) {
        if ($Policy.PSObject.Properties[$PolicyType]) {
            $Inner = $Policy.$PolicyType
            if ($Inner -and $Inner.PSObject.Properties['passwords']) {
                $Inner.PSObject.Properties.Remove('passwords')
                Write-Verbose "    Removed 'passwords' from $PolicyType (not returned by API)."
            }
        }
    }
    return $Policy
}


# ==============================================================================
# SECTION 5 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
# We fetch every group first so we can search by name.
# StellarOne groups are identified internally by UUID (a unique identifier
# like "a1b2c3d4-..."), but humans know them by name.
Write-Host "[STEP 1/5] Retrieving all agent groups from StellarOne ..." -ForegroundColor Cyan

$AllGroups = Get-AllGroups

Write-Host ""


# -- STEP 2: Verify the Source group exists ------------------------------------
Write-Host "[STEP 2/5] Locating source group '$SourceAgentGroup' ..." -ForegroundColor Cyan

$SourceGroup = Find-GroupByName -Groups $AllGroups -Name $SourceAgentGroup

if ($null -eq $SourceGroup) {
    $GroupList = ($AllGroups | ForEach-Object { "  - $($_.name)" }) -join "`n"
    Write-Error ("Source group '$SourceAgentGroup' was NOT found in StellarOne.`n" +
                 "Please verify the group name (it is case-sensitive) and try again.`n" +
                 "Available groups:`n" + $GroupList)
    exit 1
}

$SrcUuid = $SourceGroup.groupUuid
Write-Host "  [OK]  Source group found  |  UUID = $SrcUuid" -ForegroundColor Green
Write-Host ""


# -- STEP 3: Find or create the Destination group ------------------------------
Write-Host "[STEP 3/5] Locating destination group '$DestinationAgentGroup' ..." -ForegroundColor Cyan

$DestGroup = Find-GroupByName -Groups $AllGroups -Name $DestinationAgentGroup

if ($null -eq $DestGroup) {
    Write-Host "  [INFO] Group '$DestinationAgentGroup' does not exist yet - it will be created." `
        -ForegroundColor Yellow

    # Create the destination as a sibling of the source group (same parent).
    # This ensures the new group sits at the correct level of the hierarchy.
    if (-not $SourceGroup.parentGroupUuid) {
        Write-Error ("Cannot create destination group: the source group '$SourceAgentGroup' " +
                     "has no parentGroupUuid.  Please create the destination group manually " +
                     "in StellarOne and re-run the script.")
        exit 1
    }
    $DestGroup = New-StellarGroup -Name $DestinationAgentGroup `
                                  -ParentGroupUuid $SourceGroup.parentGroupUuid
} else {
    $DstUuid = $DestGroup.groupUuid
    Write-Host "  [OK]  Destination group found  |  UUID = $DstUuid" -ForegroundColor Green
}

Write-Host ""


# -- STEP 4: Retrieve the policy from the Source group -------------------------
# A group can have agents of different product types (SP, SPLM, Linux).
# We must copy the policy for each product the source group uses.
Write-Host "[STEP 4/5] Retrieving policy/policies from source group '$SourceAgentGroup' ..." `
    -ForegroundColor Cyan

# Determine which product codes to query.
# We try all three valid products and skip any that return no policy.
$ProductsToTry = @("PRODUCT_SP", "PRODUCT_SPLM", "PRODUCT_LINUX")

# Optimization: if the source group advertises its product codes, only query those.
if ($SourceGroup.productCodes -and @($SourceGroup.productCodes).Count -gt 0) {
    $Filtered = @($SourceGroup.productCodes) | Where-Object { $_ -ne "PRODUCT_UNSPECIFIED" }
    if ($Filtered.Count -gt 0) {
        $ProductsToTry = $Filtered
        $ProductList   = $ProductsToTry -join ", "
        Write-Host "  [INFO] Source group uses product(s): $ProductList" -ForegroundColor DarkGray
    }
}

$PoliciesToApply = [System.Collections.ArrayList]::new()

foreach ($ProductCode in $ProductsToTry) {
    Write-Host "  [API] Querying policy for product '$ProductCode' ..." -ForegroundColor DarkGray

    $PolicyData = Get-GroupPolicy -GroupUuid $SourceGroup.groupUuid -ProductCode $ProductCode

    if ($null -ne $PolicyData) {
        Write-Host "  [OK]  Policy found for '$ProductCode'." -ForegroundColor Green
        $PoliciesToApply.Add([PSCustomObject]@{
            ProductCode = $ProductCode
            PolicyData  = $PolicyData
        }) | Out-Null
    } else {
        Write-Host "  [SKIP] No policy configured for '$ProductCode' in source group." `
            -ForegroundColor DarkGray
    }
}

if ($PoliciesToApply.Count -eq 0) {
    Write-Warning ("No policies were found on source group '$SourceAgentGroup'.  " +
                   "There is nothing to copy.  The script will now exit.")
    exit 0
}

Write-Host ""


# -- STEP 5: Apply each policy to the Destination group -----------------------
$PolicyCount = $PoliciesToApply.Count
Write-Host "[STEP 5/5] Applying $PolicyCount policy/policies to destination group '$DestinationAgentGroup' ..." `
    -ForegroundColor Cyan

# Before writing any policy, switch the destination group to customised mode.
# New groups default to INHERITED, which means the API will reject any attempt
# to write a policy directly to them.
Write-Host "  [API] Setting destination group to customised policy mode ..." -ForegroundColor DarkGray
Set-GroupPolicyInheritance -GroupUuid $DestGroup.groupUuid `
                           -Mode "POLICY_INHERITANCE_CUSTOMIZED"
Write-Host "  [OK]  Policy inheritance set to CUSTOMIZED." -ForegroundColor Green

$SuccessCount = 0
$FailCount    = 0

foreach ($Entry in $PoliciesToApply) {
    Write-Host "  [API] Applying '$($Entry.ProductCode)' policy ..." -ForegroundColor DarkGray
    try {
        # Strip password fields -- the GET response returns them as empty strings
        # and the API will reject empty passwords on PUT.  Omitting the passwords
        # block leaves the destination group's existing passwords unchanged.
        $CleanPolicy = Remove-PasswordFields -Policy $Entry.PolicyData
        Set-GroupPolicy -GroupUuid $DestGroup.groupUuid -Policy $CleanPolicy
        Write-Host "  [OK]  '$($Entry.ProductCode)' policy applied successfully." -ForegroundColor Green
        $SuccessCount++
    }
    catch {
        Write-Warning "Failed to apply '$($Entry.ProductCode)' policy: $_"
        $FailCount++
    }
}


# ==============================================================================
# SECTION 6 - SUMMARY
# ==============================================================================

$SummaryColor = if ($FailCount -eq 0) { "Green" } else { "Yellow" }

Write-Host ""
Write-Host "==============================================================" -ForegroundColor $SummaryColor
Write-Host "  Policy Copy Summary" -ForegroundColor White
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  From (source)      : $SourceAgentGroup"
Write-Host "  Source UUID        : $($SourceGroup.groupUuid)"
Write-Host "  To (destination)   : $DestinationAgentGroup"
Write-Host "  Destination UUID   : $($DestGroup.groupUuid)"
Write-Host "--------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Policies applied   : $SuccessCount" -ForegroundColor Green
if ($FailCount -gt 0) {
    Write-Host "  Policies failed    : $FailCount" -ForegroundColor Red
}
Write-Host "==============================================================" -ForegroundColor $SummaryColor
Write-Host ""

if ($FailCount -gt 0) {
    exit 1
}
