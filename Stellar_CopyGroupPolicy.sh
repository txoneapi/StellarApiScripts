#!/usr/bin/env bash
# ==============================================================================
# FILE      : Stellar_CopyGroupPolicy.sh
# CREATED   : 2026-03-13 00:00:00
# PURPOSE   : Copies the security policy from one StellarOne agent group to
#             another, creating the destination group if it does not yet exist.
# ==============================================================================
#
# DESCRIPTION
#   This script is the Bash equivalent of Stellar_CopyGroupPolicy.ps1.
#   It automates the same administrative task in TXOne StellarOne: taking the
#   security configuration (policy) that is already set up on one group of
#   managed agents and applying it to another group.
#
#   What the script does, step by step:
#     1. Reads the StellarOne server address and API key from config files.
#     2. Connects to StellarOne and downloads the complete list of agent groups.
#     3. Verifies that the Source group exists.
#     4. Checks whether the Destination group exists; creates it if not.
#     5. Retrieves the security policy from the Source group for every product
#        type (StellarProtect, StellarProtect Legacy Mode, or Linux).
#     6. Applies each retrieved policy to the Destination group.
#
#   API endpoints used:
#     GET  /api/v1/groups                                - List all groups
#     POST /api/v1/groups                                - Create a new group
#     GET  /api/v1/policy/groups/{uuid}/product/{code}  - Read a group policy
#     PUT  /api/v1/policy/groups/{uuid}                 - Write a group policy
#
# USAGE
#   bash Stellar_CopyGroupPolicy.sh <SourceAgentGroup> <DestinationAgentGroup>
#
# PREREQUISITES
#   - bash 4.0 or later
#   - curl    : HTTP client (standard on Linux, macOS, Git Bash / MINGW64 on Windows)
#   - python3 : used as JSON processor (standard on Linux/macOS; available via
#               Python installer on Windows)
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
# This script expects exactly two positional arguments:
#   $1  -- the name of the source group to copy FROM
#   $2  -- the name of the destination group to copy TO

if [[ $# -ne 2 ]]; then
    echo "Usage  : bash Stellar_CopyGroupPolicy.sh <SourceAgentGroup> <DestinationAgentGroup>"
    echo "Example: bash Stellar_CopyGroupPolicy.sh \"Production-Line-A\" \"Production-Line-B\""
    exit 1
fi

SOURCE_GROUP_NAME="$1"
DEST_GROUP_NAME="$2"


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILES
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

echo ""
echo "=============================================================="
echo "  StellarOne - Copy Group Policy  (Bash)"
echo "=============================================================="
echo "  Server           : ${BASE_URL}"
echo "  API key (first 8): ${KEY_PREVIEW}..."
echo "  Source group     : ${SOURCE_GROUP_NAME}"
echo "  Destination group: ${DEST_GROUP_NAME}"
echo "=============================================================="
echo ""


# ==============================================================================
# SECTION 3 - JSON HELPER
# ==============================================================================
# Bash has no built-in JSON support, so we delegate all JSON parsing and
# construction to Python 3.  Python is part of the standard toolkit on
# Linux and macOS and is widely available on Windows via the Python installer.
#
# json_get PATH JSON_STRING
#   Extracts a value from a JSON string using a dot-separated key path.
#   Examples:
#     json_get "name"              "$json"    -> top-level "name" field
#     json_get "pagination.pageToken" "$json" -> nested field
#     json_get "group.groupUuid"   "$json"    -> nested "group" then "groupUuid"
#
# Prints the value, or an empty string if the key is absent/null.

json_get() {
    local path="$1"
    local json_str="$2"
    $PYTHON - "$path" <<EOF
import json, sys
path  = sys.argv[1].split(".")
data  = json.loads('''${json_str}''')
val   = data
for key in path:
    if isinstance(val, dict):
        val = val.get(key)
    else:
        val = None
    if val is None:
        break
if val is None or val == "null":
    print("")
elif isinstance(val, (dict, list)):
    print(json.dumps(val))
else:
    print(str(val))
EOF
}

# json_array_names JSON_STRING
#   Prints each group "name" value on its own line, for the groups array.

json_array_names() {
    $PYTHON -c "
import json, sys
data = json.loads(sys.argv[1])
groups = data.get('groups') or []
for g in groups:
    print(g.get('name',''))
" "$1"
}

# json_find_group_by_name GROUPS_JSON NAME
#   Prints the full JSON object of the first group whose name matches NAME.
#   Prints nothing (empty) if not found.

json_find_group_by_name() {
    $PYTHON -c "
import json, sys
data   = json.loads(sys.argv[1])
target = sys.argv[2]
groups = data.get('groups') or []
for g in groups:
    if g.get('name') == target:
        print(json.dumps(g))
        sys.exit(0)
print('')
" "$1" "$2"
}

# json_remove_passwords POLICY_JSON
#   Strips the 'passwords' key from spPolicy, splmPolicy, and linuxPolicy.
#   See SECTION 5 (Set-GroupPolicy explanation) for why this is needed.

json_remove_passwords() {
    $PYTHON -c "
import json, sys
policy = json.loads(sys.argv[1])
for ptype in ('spPolicy', 'splmPolicy', 'linuxPolicy'):
    inner = policy.get(ptype)
    if isinstance(inner, dict) and 'passwords' in inner:
        del inner['passwords']
print(json.dumps(policy))
" "$1"
}


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
#     ENDPOINT  -- URL path, e.g. "/api/v1/groups"
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

# api_request_allow_404 is identical but returns empty string on 404
# instead of aborting.  Used when querying product policies that may not exist.

api_request_allow_404() {
    local method="$1"
    local endpoint="$2"
    local url="${BASE_URL}${endpoint}"
    local raw_response

    raw_response=$(curl -sk -X "$method" \
        -H "Authorization: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -w "HTTPSTATUS:%{http_code}" \
        "$url")

    local response_body="${raw_response%HTTPSTATUS:*}"
    LAST_HTTP_CODE="${raw_response##*HTTPSTATUS:}"

    if [[ "$LAST_HTTP_CODE" -eq 404 ]]; then
        echo ""
        return 0
    fi

    if [[ "$LAST_HTTP_CODE" -ge 400 ]]; then
        echo "ERROR: API call failed: ${method} ${endpoint}  |  HTTP ${LAST_HTTP_CODE}  |  ${response_body}" >&2
        exit 1
    fi

    echo "$response_body"
}


# ==============================================================================
# SECTION 5 - HELPER FUNCTIONS
# ==============================================================================

# get_all_groups
#   Returns the JSON object {"groups": [...]} containing every group.
#
#   Why is pagination needed?
#     StellarOne returns results in "pages" instead of all at once.  Each page
#     contains up to 100 groups.  We keep requesting pages until the API stops
#     providing a pageToken (a bookmark for the next page).

get_all_groups() {
    local all_groups_json='{"groups":[]}'   # Start with an empty groups array.
    local page_token=""
    local page_number=1
    local page_size=100

    while true; do
        echo "  [API] Fetching group list - page ${page_number} ..." >&2

        local query="?limit=${page_size}&page=${page_number}"
        if [[ -n "$page_token" ]]; then
            # URL-encode the page token using Python so special characters
            # in the token do not break the URL.
            local encoded_token
            encoded_token=$($PYTHON -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$page_token")
            query="${query}&pageToken=${encoded_token}"
        fi

        local page_json
        page_json=$(api_request "GET" "/api/v1/groups${query}")

        # Merge the new page's groups into our running list using Python.
        all_groups_json=$($PYTHON -c "
import json, sys
existing = json.loads(sys.argv[1])
new_page  = json.loads(sys.argv[2])
existing['groups'].extend(new_page.get('groups') or [])
# Carry forward the pagination block so we can check pageToken.
existing['pagination'] = new_page.get('pagination', {})
print(json.dumps(existing))
" "$all_groups_json" "$page_json")

        page_token=$(json_get "pagination.pageToken" "$all_groups_json")
        if [[ -z "$page_token" ]]; then
            break
        fi
        page_number=$(( page_number + 1 ))
    done

    local total
    total=$($PYTHON -c "import json,sys; print(len(json.loads(sys.argv[1]).get('groups',[])))" "$all_groups_json")
    echo "  [INFO] Found ${total} group(s) in StellarOne." >&2

    echo "$all_groups_json"
}


# create_group NAME PARENT_UUID
#   Creates a new group under the given parent and prints the new group JSON.

create_group() {
    local name="$1"
    local parent_uuid="$2"
    echo "  [API] Creating new group '${name}' under parent UUID ${parent_uuid} ..." >&2

    # Build the JSON body using Python to handle any special characters safely.
    local body
    body=$($PYTHON -c "import json,sys; print(json.dumps({'name':sys.argv[1],'parentGroupUuid':sys.argv[2]}))" "$name" "$parent_uuid")

    local response
    response=$(api_request "POST" "/api/v1/groups" "$body")

    local new_uuid
    new_uuid=$(json_get "group.groupUuid" "$response")
    echo "  [OK]  Group '${name}' created  |  UUID = ${new_uuid}" >&2

    # Return the full group object (inside the response).
    $PYTHON -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get('group',{})))" "$response"
}


# set_policy_inheritance GROUP_UUID MODE
#   Switches a group between inherited and customised policy mode.
#   MODE is one of:
#     POLICY_INHERITANCE_CUSTOMIZED  -- group has its own independent policy
#     POLICY_INHERITANCE_INHERITED   -- group copies its parent's policy

set_policy_inheritance() {
    local group_uuid="$1"
    local mode="$2"
    local body
    body=$($PYTHON -c "import json,sys; print(json.dumps({'policyInheritance':sys.argv[1]}))" "$mode")
    api_request "PUT" "/api/v1/groups/${group_uuid}" "$body" > /dev/null
}


# apply_policy GROUP_UUID POLICY_JSON
#   Applies (writes) a security policy to a destination group.

apply_policy() {
    local group_uuid="$1"
    local policy_json="$2"
    local body
    body=$($PYTHON -c "import json,sys; print(json.dumps({'policy':json.loads(sys.argv[1])}))" "$policy_json")
    api_request "PUT" "/api/v1/policy/groups/${group_uuid}" "$body" > /dev/null
}


# ==============================================================================
# SECTION 6 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
echo "[STEP 1/5] Retrieving all agent groups from StellarOne ..."
ALL_GROUPS_JSON=$(get_all_groups)
echo ""


# -- STEP 2: Verify the Source group exists ------------------------------------
echo "[STEP 2/5] Locating source group '${SOURCE_GROUP_NAME}' ..."

SOURCE_GROUP=$(json_find_group_by_name "$ALL_GROUPS_JSON" "$SOURCE_GROUP_NAME")

if [[ -z "$SOURCE_GROUP" ]]; then
    echo "ERROR: Source group '${SOURCE_GROUP_NAME}' was NOT found in StellarOne."
    echo "Please verify the group name (it is case-sensitive) and try again."
    echo "Available groups:"
    json_array_names "$ALL_GROUPS_JSON" | sed 's/^/  - /'
    exit 1
fi

SRC_UUID=$(json_get "groupUuid" "$SOURCE_GROUP")
echo "  [OK]  Source group found  |  UUID = ${SRC_UUID}"
echo ""


# -- STEP 3: Find or create the Destination group ------------------------------
echo "[STEP 3/5] Locating destination group '${DEST_GROUP_NAME}' ..."

DEST_GROUP=$(json_find_group_by_name "$ALL_GROUPS_JSON" "$DEST_GROUP_NAME")

if [[ -z "$DEST_GROUP" ]]; then
    echo "  [INFO] Group '${DEST_GROUP_NAME}' does not exist yet - it will be created."

    PARENT_UUID=$(json_get "parentGroupUuid" "$SOURCE_GROUP")
    if [[ -z "$PARENT_UUID" ]]; then
        echo "ERROR: Source group '${SOURCE_GROUP_NAME}' has no parentGroupUuid."
        echo "Please create the destination group manually in StellarOne and re-run."
        exit 1
    fi

    DEST_GROUP=$(create_group "$DEST_GROUP_NAME" "$PARENT_UUID")
else
    DST_UUID=$(json_get "groupUuid" "$DEST_GROUP")
    echo "  [OK]  Destination group found  |  UUID = ${DST_UUID}"
fi

DEST_UUID=$(json_get "groupUuid" "$DEST_GROUP")
echo ""


# -- STEP 4: Retrieve the policy from the Source group -------------------------
# A group can have agents of different product types (SP, SPLM, Linux).
# We must copy the policy for each product the source group uses.
echo "[STEP 4/5] Retrieving policy/policies from source group '${SOURCE_GROUP_NAME}' ..."

# Determine which product codes to query.
# If the source group advertises its product codes, use those; otherwise try all three.
PRODUCTS_TO_TRY="PRODUCT_SP PRODUCT_SPLM PRODUCT_LINUX"

SOURCE_PRODUCT_CODES=$($PYTHON -c "
import json, sys
g = json.loads(sys.argv[1])
codes = [c for c in (g.get('productCodes') or []) if c != 'PRODUCT_UNSPECIFIED']
print(' '.join(codes))
" "$SOURCE_GROUP")

if [[ -n "$SOURCE_PRODUCT_CODES" ]]; then
    PRODUCTS_TO_TRY="$SOURCE_PRODUCT_CODES"
    echo "  [INFO] Source group uses product(s): ${PRODUCTS_TO_TRY}"
fi

# We store found policies as parallel arrays: product codes and JSON strings.
POLICY_PRODUCTS=()
POLICY_DATA=()

for PRODUCT_CODE in $PRODUCTS_TO_TRY; do
    echo "  [API] Querying policy for product '${PRODUCT_CODE}' ..."

    POLICY_JSON=$(api_request_allow_404 "GET" \
        "/api/v1/policy/groups/${SRC_UUID}/product/${PRODUCT_CODE}")

    if [[ -n "$POLICY_JSON" ]]; then
        echo "  [OK]  Policy found for '${PRODUCT_CODE}'."
        POLICY_PRODUCTS+=("$PRODUCT_CODE")
        POLICY_DATA+=("$POLICY_JSON")
    else
        echo "  [SKIP] No policy configured for '${PRODUCT_CODE}' in source group."
    fi
done

if [[ ${#POLICY_PRODUCTS[@]} -eq 0 ]]; then
    echo "WARNING: No policies were found on source group '${SOURCE_GROUP_NAME}'."
    echo "There is nothing to copy. The script will now exit."
    exit 0
fi

echo ""


# -- STEP 5: Apply each policy to the Destination group -----------------------
POLICY_COUNT=${#POLICY_PRODUCTS[@]}
echo "[STEP 5/5] Applying ${POLICY_COUNT} policy/policies to destination group '${DEST_GROUP_NAME}' ..."

# Before writing any policy, switch the destination group to customised mode.
# New groups default to INHERITED, which means the API will reject policy writes.
echo "  [API] Setting destination group to customised policy mode ..."
set_policy_inheritance "$DEST_UUID" "POLICY_INHERITANCE_CUSTOMIZED"
echo "  [OK]  Policy inheritance set to CUSTOMIZED."

SUCCESS_COUNT=0
FAIL_COUNT=0

for i in "${!POLICY_PRODUCTS[@]}"; do
    PRODUCT_CODE="${POLICY_PRODUCTS[$i]}"
    POLICY_JSON="${POLICY_DATA[$i]}"

    echo "  [API] Applying '${PRODUCT_CODE}' policy ..."

    # Strip password fields -- the GET response returns them as empty strings
    # and the API will reject empty passwords on PUT.  Omitting the passwords
    # block leaves the destination group's existing passwords unchanged.
    CLEAN_POLICY=$(json_remove_passwords "$POLICY_JSON")

    if apply_policy "$DEST_UUID" "$CLEAN_POLICY"; then
        echo "  [OK]  '${PRODUCT_CODE}' policy applied successfully."
        SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
    else
        echo "  [FAIL] Failed to apply '${PRODUCT_CODE}' policy." >&2
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    fi
done


# ==============================================================================
# SECTION 7 - SUMMARY
# ==============================================================================

echo ""
echo "=============================================================="
echo "  Policy Copy Summary"
echo "--------------------------------------------------------------"
echo "  From (source)      : ${SOURCE_GROUP_NAME}"
echo "  Source UUID        : ${SRC_UUID}"
echo "  To (destination)   : ${DEST_GROUP_NAME}"
echo "  Destination UUID   : ${DEST_UUID}"
echo "--------------------------------------------------------------"
echo "  Policies applied   : ${SUCCESS_COUNT}"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "  Policies failed    : ${FAIL_COUNT}"
fi
echo "=============================================================="
echo ""

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
