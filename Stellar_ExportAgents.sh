#!/usr/bin/env bash
# ==============================================================================
# FILE      : Stellar_ExportAgents.sh
# CREATED   : 2026-03-14
# PURPOSE   : Exports all agents from StellarOne to a CSV file that reflects
#             the full group tree structure, with one column per hierarchy level.
# ==============================================================================
#
# DESCRIPTION
#   This script is the Bash equivalent of Stellar_ExportAgents.ps1.
#   It connects to a TXOne StellarOne management server, downloads every
#   managed agent and every agent group, and writes a CSV file where each
#   row is one agent and the columns describe its position in the group tree.
#
#   CSV column layout:
#     Hostname    - The agent's hostname (computer name).
#     IP          - The agent's IP address as reported by StellarOne.
#     Online      - "Yes" if the agent is currently connected, "No" otherwise.
#     DirectGroup - The name of the group the agent belongs to directly.
#                   Repeated in a fixed column for easy sorting/filtering.
#     All         - L1: always the root group, named "All" in StellarOne.
#     L2 .. Ln    - One column per additional level of nesting.
#     FullPath    - The complete path, e.g. "All > SiteA > Production > Line-1".
#
#   API endpoints used:
#     GET /api/v1/groups?limit=100&page=N&pageToken=T  - List all groups
#     GET /api/v1/agents?limit=100&page=N&pageToken=T  - List all agents
#
# USAGE
#   bash Stellar_ExportAgents.sh [output_path]
#
#   output_path  Optional.  Full path (or filename) for the CSV file.
#                Default: StellarOne_Agents_YYYYMMDD_HHMMSS.csv in the
#                same folder as this script.
#
# PREREQUISITES
#   - bash 4.0 or later
#   - curl    : HTTP client (standard on Linux, macOS, Git Bash / MINGW64 on Windows)
#   - python3 : used as JSON processor and CSV writer (standard on Linux/macOS;
#               available via Python installer on Windows)
#   - StellarOne.conf in the same folder as this script
#   - Network access to the StellarOne management server
#
# TESTED ON
#   - GNU bash 5.2 / MINGW64 (Windows) with Python 3.12 and curl 8.17
#   - GNU bash 5.1 / Ubuntu 22.04 with Python 3.10 and curl 7.81
# ==============================================================================

# "set -euo pipefail" is a best practice for robust bash scripts:
#   -e  : Exit immediately if any command fails (returns non-zero).
#   -u  : Treat unset variables as errors (prevents silent bugs).
#   -o pipefail : A pipeline fails if ANY command in it fails, not just the last.
set -euo pipefail


# ==============================================================================
# PYTHON COMMAND DETECTION
# ==============================================================================
# Linux/macOS ship Python 3 as "python3".
# Windows (MINGW64/Git Bash) typically installs it as "python".
# We detect whichever is available and use that throughout the script.

if command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo "ERROR: Python 3 is required but was not found on this system."
    echo "Install Python 3 from https://www.python.org and ensure it is in your PATH."
    exit 1
fi


# ==============================================================================
# SECTION 1 - COMMAND-LINE ARGUMENTS
# ==============================================================================
# This script accepts one optional argument:
#   $1  -- the output CSV file path (default: auto-generated in script dir)

if [[ $# -gt 1 ]]; then
    echo "Usage  : bash Stellar_ExportAgents.sh [output_path]"
    echo "Example: bash Stellar_ExportAgents.sh /tmp/agents.csv"
    exit 1
fi


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILE
# ==============================================================================
# All configuration lives in a single file alongside the script:
#
#   StellarOne.conf  ->  server URL and API authentication key
#
# Copy stellarOne_example.conf to StellarOne.conf and fill in your values.
# Never commit StellarOne.conf to version control -- it contains credentials.

# SCRIPT_DIR resolves to the folder where this .sh file is saved, even when
# the script is called from a different working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONF_PATH="${SCRIPT_DIR}/StellarOne.conf"

if [[ ! -f "$CONF_PATH" ]]; then
    echo "ERROR: Required configuration file not found: $CONF_PATH"
    echo "Please copy stellarOne_example.conf to StellarOne.conf and fill in your values."
    exit 1
fi

# Parse StellarOne.conf -- expected format:
#   StellarOneURL="https://x.x.x.x"
#   ApiKey="<long hex string>"
if ! grep -qE 'StellarOneURL="[^"]+"' "$CONF_PATH"; then
    echo "ERROR: Could not read the StellarOne server URL from: $CONF_PATH"
    echo 'Expected a line like:  StellarOneURL="https://192.168.1.1"'
    exit 1
fi
BASE_URL=$(grep -oE 'StellarOneURL="[^"]+"' "$CONF_PATH" | sed 's/StellarOneURL="//;s/"$//')
BASE_URL="${BASE_URL%/}"

if ! grep -qE 'ApiKey="[^"]+"' "$CONF_PATH"; then
    echo "ERROR: Could not read the API key from: $CONF_PATH"
    echo 'Expected a line like:  ApiKey="abc123..."'
    exit 1
fi
API_KEY=$(grep -oE 'ApiKey="[^"]+"' "$CONF_PATH" | sed 's/ApiKey="//;s/"$//')
KEY_PREVIEW="${API_KEY:0:8}"

# Resolve the output file path.
# If not provided as an argument, generate a timestamped filename in SCRIPT_DIR.
if [[ $# -eq 1 ]]; then
    OUTPUT_FILE="$1"
else
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_FILE="${SCRIPT_DIR}/StellarOne_Agents_${TIMESTAMP}.csv"
fi

echo ""
echo "=============================================================="
echo "  StellarOne - Export Agents  (Bash)"
echo "=============================================================="
echo "  Server           : ${BASE_URL}"
echo "  API key (first 8): ${KEY_PREVIEW}..."
echo "  Output file      : ${OUTPUT_FILE}"
echo "=============================================================="
echo ""


# ==============================================================================
# SECTION 3 - TEMP FILE SETUP
# ==============================================================================
# All JSON data is stored in temp files rather than shell variables.
#
# Why temp files instead of variables?
#   With hundreds of groups and agents the JSON can be several hundred kilobytes.
#   Passing that as a command-line argument (e.g. python -c "..." "$BIG_JSON")
#   hits the OS argument-length limit (ARG_MAX) and causes "Argument list too
#   long" errors.  Temp files have no such limit.
#
#   mktemp creates a uniquely-named empty file in the system temp directory.
#   The trap command ensures the files are deleted automatically when the script
#   exits, whether normally or due to an error.

TEMP_GROUPS=$(mktemp)   # Accumulates all group objects across pages.
TEMP_AGENTS=$(mktemp)   # Accumulates all agent objects across pages.
TEMP_PAGE=$(mktemp)     # Holds the current API page response (reused each loop).
trap 'rm -f "$TEMP_GROUPS" "$TEMP_AGENTS" "$TEMP_PAGE"' EXIT

# Initialise with empty JSON arrays.
echo '[]' > "$TEMP_GROUPS"
echo '[]' > "$TEMP_AGENTS"


# ==============================================================================
# SECTION 4 - API REQUEST FUNCTION
# ==============================================================================
# api_request METHOD ENDPOINT [BODY]
#
#   Central function that sends any HTTP request to StellarOne.
#
#   Why have one shared function?
#     Using a single wrapper ensures that every API call uses the same server
#     URL, headers, and error-handling logic.
#
#   Parameters:
#     METHOD    -- "GET", "POST", or "PUT"
#     ENDPOINT  -- URL path, e.g. "/api/v1/agents"
#     BODY      -- Optional JSON string to send as the request body
#
#   Returns:
#     Prints the response body to stdout.
#     Exits with code 1 on HTTP errors.
#
#   The -s flag makes curl silent (no progress bar).
#   The -k flag tells curl to skip SSL certificate verification (self-signed).
#   The -w flag appends the HTTP status code after the response body,
#     separated by the unique marker "HTTPSTATUS:" so we can split them.

LAST_HTTP_CODE=0   # Global: populated after each api_request call.

api_request() {
    local method="$1"
    local endpoint="$2"
    local body="${3:-}"
    local url="${BASE_URL}${endpoint}"
    local curl_args=(-sk -X "$method"
        -H "Authorization: ${API_KEY}"
        -H "Content-Type: application/json"
        -H "Accept: application/json"
        -w "HTTPSTATUS:%{http_code}"
    )

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
    fi

    local raw_response
    raw_response=$(curl "${curl_args[@]}" "$url")

    # Split the response body from the appended "HTTPSTATUS:<code>".
    local response_body="${raw_response%HTTPSTATUS:*}"
    LAST_HTTP_CODE="${raw_response##*HTTPSTATUS:}"

    if [[ "$LAST_HTTP_CODE" -ge 400 ]]; then
        echo "ERROR: API call failed: ${method} ${endpoint}  |  HTTP ${LAST_HTTP_CODE}  |  ${response_body}" >&2
        exit 1
    fi

    echo "$response_body"
}


# ==============================================================================
# SECTION 5 - DATA FETCHING FUNCTIONS
# ==============================================================================

# fetch_all  ENDPOINT  ARRAY_KEY  ACCUM_FILE
#
#   Generic paginated fetcher.  Reads every page from ENDPOINT, extracts
#   the array at ARRAY_KEY from each response, and appends the items to
#   ACCUM_FILE (a JSON array file initialised to "[]" before calling).
#
#   Why a shared fetch function?
#     Both groups and agents use identical pagination logic.  One function
#     avoids duplicating the loop, the URL-encoding, and the merge step.
#
#   Parameters:
#     ENDPOINT   -- API path prefix, e.g. "/api/v1/groups"
#     ARRAY_KEY  -- JSON key that holds the list in each response ("groups" / "agents")
#     ACCUM_FILE -- path to the temp file accumulating results

fetch_all() {
    local endpoint="$1"
    local array_key="$2"
    local accum_file="$3"

    local page_token=""
    local page_number=1
    local page_size=100

    while true; do
        echo "  [API] Fetching ${array_key} list - page ${page_number} ..." >&2

        local query="?limit=${page_size}&page=${page_number}"
        if [[ -n "$page_token" ]]; then
            # URL-encode the page token using Python so special characters
            # in the token do not break the URL.
            local encoded_token
            encoded_token=$($PYTHON -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
                "$page_token")
            query="${query}&pageToken=${encoded_token}"
        fi

        # Fetch one page and write it to the reusable TEMP_PAGE file.
        # Writing to a file instead of a variable means the response size
        # (potentially large) never touches shell argument limits.
        api_request "GET" "${endpoint}${query}" > "$TEMP_PAGE"

        # Append this page's items to the accumulator, and extract the next
        # pageToken, using Python reading both files.
        page_token=$(STELLAR_ACCUM_FILE="$accum_file" \
                     STELLAR_PAGE_FILE="$TEMP_PAGE" \
                     STELLAR_ARRAY_KEY="$array_key" \
                     $PYTHON << 'PYEOF'
import json, os

accum_file = os.environ["STELLAR_ACCUM_FILE"]
page_file  = os.environ["STELLAR_PAGE_FILE"]
array_key  = os.environ["STELLAR_ARRAY_KEY"]

with open(accum_file, encoding="utf-8") as f:
    accumulated = json.load(f)

with open(page_file, encoding="utf-8") as f:
    page = json.load(f)

items = page.get(array_key) or []
accumulated.extend(items)

# Write the updated accumulator back to the same file.
with open(accum_file, "w", encoding="utf-8") as f:
    json.dump(accumulated, f)

# Print the next page token (empty string if this was the last page).
token = (page.get("pagination") or {}).get("pageToken") or ""
print(token)
PYEOF
)

        if [[ -z "$page_token" ]]; then
            break
        fi
        page_number=$(( page_number + 1 ))
    done

    # Print the total count to stderr so it appears in the console.
    local total
    total=$(STELLAR_ACCUM_FILE="$accum_file" $PYTHON -c \
        "import json,os; print(len(json.load(open(os.environ['STELLAR_ACCUM_FILE']))))")
    echo "  [INFO] Found ${total} ${array_key}." >&2
}


# ==============================================================================
# SECTION 6 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
echo "[STEP 1/4] Retrieving all agent groups from StellarOne ..."
fetch_all "/api/v1/groups" "groups" "$TEMP_GROUPS"
echo ""


# -- STEP 2: Load the complete agent list --------------------------------------
echo "[STEP 2/4] Retrieving all agents from StellarOne ..."
fetch_all "/api/v1/agents" "agents" "$TEMP_AGENTS"
echo ""


# -- STEP 3 & 4: Resolve hierarchy and write CSV -------------------------------
# Bash has no built-in JSON support or CSV writing capability.
# We hand all the complex data processing off to Python via a heredoc.
#
# The group and agent data are already in TEMP_GROUPS and TEMP_AGENTS.
# We pass the file paths and the output destination via environment variables.
# Using environment variables (rather than arguments) keeps the Python call
# clean and avoids any quoting issues with paths that contain spaces.

echo "[STEP 3/4] Resolving group hierarchy for each agent ..."

STELLAR_GROUPS_FILE="$TEMP_GROUPS" \
STELLAR_AGENTS_FILE="$TEMP_AGENTS" \
STELLAR_OUTPUT_FILE="$OUTPUT_FILE" \
$PYTHON << 'PYEOF'
# ============================================================================
# Embedded Python: resolve group paths and write CSV
# ============================================================================
import json
import csv
import os
import sys

groups_file = os.environ["STELLAR_GROUPS_FILE"]
agents_file = os.environ["STELLAR_AGENTS_FILE"]
output_file = os.environ["STELLAR_OUTPUT_FILE"]

# Load the data from the temp files written by the fetch_all function.
with open(groups_file, encoding="utf-8") as f:
    all_groups = json.load(f)
with open(agents_file, encoding="utf-8") as f:
    all_agents = json.load(f)

# -----------------------------------------------------------------------
# Build a fast UUID-keyed dictionary for group lookups.
#
# Why build a map?
#   The agent data only tells us the groupUuid of the agent's direct parent.
#   To walk up the tree (find grandparent, great-grandparent, etc.) we need
#   to quickly look up any group by its UUID.  A dictionary gives O(1) lookup
#   time instead of scanning the full list on every step.
# -----------------------------------------------------------------------
group_map = {g["groupUuid"]: g for g in all_groups if "groupUuid" in g}


def resolve_path(group_uuid):
    """
    Walk the group tree upward from group_uuid to the root, collecting
    names, then reverse to get [root, ..., leaf].

    A visited set prevents infinite loops in case of a malformed tree
    with circular parent references.
    """
    path    = []
    visited = set()
    current = group_uuid

    while current and current not in visited:
        visited.add(current)
        group = group_map.get(current)
        if group is None:
            break
        path.append(group.get("name", "(unnamed)"))
        current = group.get("parentGroupUuid") or ""

    path.reverse()
    return path


# -----------------------------------------------------------------------
# Resolve every agent's hierarchy path.
# -----------------------------------------------------------------------
resolved = []
for agent in all_agents:
    group_uuid   = agent.get("groupUuid") or ""
    path         = resolve_path(group_uuid) if group_uuid else []
    direct_group = path[-1] if path else ""
    full_path    = " > ".join(path)
    online_str   = "Yes" if agent.get("agentOnlineStatus", False) else "No"

    resolved.append({
        "hostname":     agent.get("hostname",  ""),
        "ip":           agent.get("ipAddress", ""),
        "online":       online_str,
        "direct_group": direct_group,
        "path":         path,
        "full_path":    full_path,
    })

# Find the maximum depth so we know how many "L" columns to create.
max_depth = max((len(a["path"]) for a in resolved), default=1)

print("  [INFO] Maximum group nesting depth: " + str(max_depth), flush=True)

# Build the dynamic column header list.
#   Fixed columns : Hostname, IP, Online, DirectGroup
#   Tree columns  : "All" (always L1), then L2, L3, ... Ln
#   Trailing column: FullPath
tree_headers = ["All"] + [f"L{i}" for i in range(2, max_depth + 1)]
fieldnames   = ["Hostname", "IP", "Online", "DirectGroup"] + tree_headers + ["FullPath"]

# Write the CSV file.
# utf-8-sig writes a UTF-8 BOM so Excel auto-detects the encoding on Windows.
# newline="" prevents the csv module from writing double line endings on Windows.
print("[STEP 4/4] Writing CSV file: " + output_file, flush=True)

with open(output_file, "w", newline="", encoding="utf-8-sig") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()

    for agent in resolved:
        path = agent["path"]
        row  = {
            "Hostname":    agent["hostname"],
            "IP":          agent["ip"],
            "Online":      agent["online"],
            "DirectGroup": agent["direct_group"],
        }
        for idx, header in enumerate(tree_headers):
            row[header] = path[idx] if idx < len(path) else ""
        row["FullPath"] = agent["full_path"]
        writer.writerow(row)

online_count  = sum(1 for a in resolved if a["online"] == "Yes")
offline_count = len(resolved) - online_count

print("  [OK]  CSV written: " + str(len(resolved)) + " agent(s) exported.", flush=True)
print("", flush=True)
print("==============================================================", flush=True)
print("  Agent Export Summary", flush=True)
print("--------------------------------------------------------------", flush=True)
print("  Total agents exported : " + str(len(resolved)), flush=True)
print("  Online                : " + str(online_count), flush=True)
print("  Offline               : " + str(offline_count), flush=True)
print("  Max group depth       : " + str(max_depth), flush=True)
print("  CSV columns           : " + str(len(fieldnames)), flush=True)
print("--------------------------------------------------------------", flush=True)
print("  Output file           : " + output_file, flush=True)
print("==============================================================", flush=True)
print("", flush=True)
PYEOF
