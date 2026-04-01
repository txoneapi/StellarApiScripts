#!/usr/bin/env bash
# ==============================================================================
# FILE      : Stellar_ImportIOCs.sh
# CREATED   : 2026-04-01
# PURPOSE   : Reads a list of file hashes (IOCs) from IOCs.csv and adds each
#             one as a User-Defined Suspicious Object (UDSO) in TXOne StellarOne.
# ==============================================================================
#
# DESCRIPTION
#   Reads IOCs.csv (hash, description per line) and merges each hash into the
#   global policy's userDefinedSuspiciousObjects list for each active product
#   type (StellarProtect and StellarProtect Legacy Mode).
#
#   How it works:
#     1. Reads the StellarOne server address and API key from StellarOne.conf.
#     2. Parses the CSV file; skips blank lines, comments, and MD5 hashes.
#     3. For each product type (SP, SPLM), GETs the current global policy.
#     4. Merges the new hashes into the existing UDSO list (no duplicates).
#     5. PUTs the updated policy back.
#
#   Supported hash types (StellarOne API limitation):
#     SHA-1   -- 40 hex characters
#     SHA-256 -- 64 hex characters
#     MD5 is NOT supported by the StellarOne UDSO API and will be skipped.
#
#   NOTE: StellarOne does not support a per-hash BLOCK/LOG action.
#     The action is a policy-level setting configured in the StellarOne console.
#     The 'action' column in the CSV is accepted for documentation but NOT sent
#     to the API.
#
#   API endpoints used:
#     GET /api/v1/policy/global/{product_code}  - Read current global policy
#     PUT /api/v1/policy/global                 - Write updated global policy
#
# USAGE
#   bash Stellar_ImportIOCs.sh [<path-to-csv>]
#
#   If no path is given the script looks for IOCs.csv in the same folder.
#
# PREREQUISITES
#   - bash 4.0 or later
#   - curl    : HTTP client
#   - python3 : used as JSON processor
#   - StellarOne.conf in the same folder as this script
#   - Network access to the StellarOne management server
#
# TESTED ON
#   - GNU bash 5.2 / MINGW64 (Windows) with Python 3.12 and curl 8.17
#   - GNU bash 5.1 / Ubuntu 22.04 with Python 3.10 and curl 7.81
# ==============================================================================

set -euo pipefail


# ==============================================================================
# PYTHON COMMAND DETECTION
# ==============================================================================
# Linux/macOS ship Python 3 as "python3".
# Windows (MINGW64/Git Bash) typically installs it as "python".

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

CSV_PATH_ARG="${1:-}"


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILES
# ==============================================================================
# All configuration lives in StellarOne.conf alongside the script.
# Never commit StellarOne.conf to version control -- it contains credentials.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_PATH="${SCRIPT_DIR}/StellarOne.conf"

if [[ ! -f "$CONF_PATH" ]]; then
    echo "ERROR: Required configuration file not found: $CONF_PATH"
    echo "Please copy stellarOne_example.conf to StellarOne.conf and fill in your values."
    exit 1
fi

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

# Resolve CSV path.
if [[ -n "$CSV_PATH_ARG" ]]; then
    CSV_PATH="$CSV_PATH_ARG"
else
    CSV_PATH="${SCRIPT_DIR}/IOCs.csv"
fi

if [[ ! -f "$CSV_PATH" ]]; then
    echo "ERROR: IOC file not found: $CSV_PATH"
    echo "Create the file or pass its path as the first argument."
    exit 1
fi

echo ""
echo "=============================================================="
echo "  StellarOne - Import IOCs  (Bash)"
echo "=============================================================="
echo "  Server           : ${BASE_URL}"
echo "  API key (first 8): ${KEY_PREVIEW}..."
echo "  IOC file         : ${CSV_PATH}"
echo "=============================================================="
echo ""


# ==============================================================================
# SECTION 3 - JSON HELPER
# ==============================================================================
# Bash has no built-in JSON support.  We delegate all JSON work to Python 3.

# json_get PATH JSON_STRING
#   Extracts a value from a JSON string using a dot-separated key path.

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


# ==============================================================================
# SECTION 4 - API REQUEST FUNCTION
# ==============================================================================
# api_request METHOD ENDPOINT [BODY]
#
#   Sends an HTTP request to StellarOne and prints the response body.
#   Exits with code 1 on HTTP errors.
#
#   The -s flag makes curl silent (no progress bar).
#   The -k flag tells curl to skip SSL certificate verification (self-signed).
#   The -w flag appends the HTTP status code after the response body.

LAST_HTTP_CODE=0

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

    local response_body="${raw_response%HTTPSTATUS:*}"
    LAST_HTTP_CODE="${raw_response##*HTTPSTATUS:}"

    if [[ "$LAST_HTTP_CODE" -ge 400 ]]; then
        echo "ERROR: API call failed: ${method} ${endpoint}  |  HTTP ${LAST_HTTP_CODE}  |  ${response_body}" >&2
        exit 1
    fi

    echo "$response_body"
}

# api_request_allow_404 -- same as api_request but returns empty string on 404.

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

    # Some curl implementations (notably on Windows/MINGW64) return HTTP status
    # 000 when the server is unreachable instead of a non-zero exit code.
    # On other platforms curl may exit non-zero directly (codes 6, 7, etc.),
    # which set -euo pipefail would catch upstream.  This guard handles 000.
    if [[ "$LAST_HTTP_CODE" -eq 0 ]]; then
        echo "ERROR: Could not connect to ${BASE_URL} -- is the server reachable?" >&2
        exit 1
    fi

    if [[ "$LAST_HTTP_CODE" -eq 404 ]]; then
        echo ""; return 0
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

# detect_hash_type HASH
#   Prints "TYPE_SHA1", "TYPE_SHA256", "MD5" (unsupported), or "INVALID".

detect_hash_type() {
    local hash="$1"
    local len="${#hash}"

    # Must be all hex characters.
    if ! [[ "$hash" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "INVALID"; return
    fi

    case "$len" in
        40) echo "TYPE_SHA1"   ;;
        64) echo "TYPE_SHA256" ;;
        32) echo "MD5"         ;;
         *) echo "INVALID"     ;;
    esac
}


# get_udso_list POLICY_JSON POLICY_KEY
#   Extracts the existing UDSO list array from a policy response.
#   Prints a JSON array (possibly empty "[]").

get_udso_list() {
    $PYTHON -c "
import json, sys
resp = json.loads(sys.argv[1])
key  = sys.argv[2]
inner = resp.get(key) or {}
udso  = inner.get('userDefinedSuspiciousObjects') or {}
lst   = udso.get('list') or []
print(json.dumps(lst))
" "$1" "$2"
}


# merge_iocs EXISTING_LIST_JSON NEW_IOCS_JSON
#   Merges new IOC entries into the existing list, skipping duplicates.
#   NEW_IOCS_JSON is a JSON array of {"value","notes","type"} objects.
#   Prints a JSON object: {"merged": [...], "added": N, "skipped": N}

merge_iocs() {
    $PYTHON -c "
import json, sys
existing = json.loads(sys.argv[1])
new_iocs = json.loads(sys.argv[2])

existing_vals = {e.get('value','').lower() for e in existing}
merged  = list(existing)
added   = 0
skipped = 0

for ioc in new_iocs:
    val = ioc['value'].lower()
    if val in existing_vals:
        skipped += 1
    else:
        merged.append({'value': val, 'notes': ioc['notes'], 'type': ioc['type']})
        existing_vals.add(val)
        added += 1

print(json.dumps({'merged': merged, 'added': added, 'skipped': skipped}))
" "$1" "$2"
}


# put_global_policy POLICY_KEY UDSO_LIST_JSON
#   Writes the updated UDSO list back to the global policy for one product.
#   Uses replace-on-presence semantics: only the UDSO block is sent.

put_global_policy() {
    local policy_key="$1"
    local udso_list_json="$2"

    local body
    body=$($PYTHON -c "
import json, sys
key      = sys.argv[1]
udso_lst = json.loads(sys.argv[2])
body = {'policy': {key: {'userDefinedSuspiciousObjects': {'list': udso_lst}}}}
print(json.dumps(body))
" "$policy_key" "$udso_list_json")

    api_request "PUT" "/api/v1/policy/global" "$body" > /dev/null
}


# ==============================================================================
# SECTION 6 - PARSE THE CSV FILE
# ==============================================================================
# Supported layouts:
#   hash,description           -- 2 columns (action column optional)
#   hash,description,action    -- 3 columns (action logged but not sent to API)

echo "[STEP 1/3] Reading IOCs from CSV ..."

# We build a JSON array of valid IOC objects and track counters.
VALID_IOCS_JSON="[]"
VALID_COUNT=0
SKIPPED_MD5=0
SKIPPED_BAD=0
LINE_NO=0

while IFS= read -r RAW_LINE || [[ -n "$RAW_LINE" ]]; do
    LINE_NO=$(( LINE_NO + 1 ))
    STRIPPED="${RAW_LINE%$'\r'}"   # Strip Windows CR if present.
    STRIPPED="${STRIPPED## }"
    STRIPPED="${STRIPPED%% }"

    # Skip blank lines and comment lines.
    [[ -z "$STRIPPED" || "${STRIPPED:0:1}" == "#" ]] && continue

    # Split into columns (up to 3).
    IFS=',' read -r HASH_VAL DESC_VAL ACTION_VAL REST <<< "$STRIPPED" || true
    HASH_VAL="${HASH_VAL## }"; HASH_VAL="${HASH_VAL%% }"
    DESC_VAL="${DESC_VAL## }"; DESC_VAL="${DESC_VAL%% }"
    ACTION_VAL="${ACTION_VAL## }"; ACTION_VAL="${ACTION_VAL%% }"

    # Skip header row.
    [[ "${HASH_VAL,,}" == "hash" ]] && continue

    # Need at least a hash and a description.
    if [[ -z "$DESC_VAL" ]]; then
        echo "  [WARN] Line ${LINE_NO}: expected at least 2 columns -- skipping."
        SKIPPED_BAD=$(( SKIPPED_BAD + 1 ))
        continue
    fi

    HASH_TYPE=$(detect_hash_type "$HASH_VAL")

    if [[ "$HASH_TYPE" == "MD5" ]]; then
        echo "  [SKIP] Line ${LINE_NO}: MD5 hash not supported by StellarOne UDSO API -- ${HASH_VAL}"
        SKIPPED_MD5=$(( SKIPPED_MD5 + 1 ))
        continue
    fi

    if [[ "$HASH_TYPE" == "INVALID" ]]; then
        echo "  [SKIP] Line ${LINE_NO}: '${HASH_VAL}' -- not a recognised SHA-1 or SHA-256 hash."
        SKIPPED_BAD=$(( SKIPPED_BAD + 1 ))
        continue
    fi

    # Append to the JSON array of valid IOCs.
    VALID_IOCS_JSON=$($PYTHON -c "
import json, sys
lst  = json.loads(sys.argv[1])
lst.append({'value': sys.argv[2].lower(), 'notes': sys.argv[3], 'type': sys.argv[4]})
print(json.dumps(lst))
" "$VALID_IOCS_JSON" "$HASH_VAL" "$DESC_VAL" "$HASH_TYPE")

    VALID_COUNT=$(( VALID_COUNT + 1 ))

done < "$CSV_PATH"

echo "  [INFO] ${VALID_COUNT} valid IOC(s) ready to import."
[[ $SKIPPED_MD5 -gt 0 ]] && echo "  [INFO] ${SKIPPED_MD5} MD5 hash(es) skipped -- not supported by StellarOne UDSO API."
[[ $SKIPPED_BAD -gt 0 ]] && echo "  [INFO] ${SKIPPED_BAD} row(s) skipped due to format errors."
echo ""

if [[ "$VALID_COUNT" -eq 0 ]]; then
    echo "Nothing to import.  Verify that the CSV contains SHA-1 or SHA-256 hashes."
    exit 0
fi


# ==============================================================================
# SECTION 7 - MAIN WORKFLOW: MERGE IOCS INTO EACH PRODUCT POLICY
# ==============================================================================
# StellarOne stores UDSOs inside the global policy, once per product type.
# We update both StellarProtect (spPolicy) and StellarProtect Legacy Mode
# (splmPolicy) so that agents of both types receive the new hashes.

TOTAL_ADDED=0
TOTAL_DUPES=0
TOTAL_FAILED=0

echo "[STEP 2/3] Merging ${VALID_COUNT} IOC(s) into global policy ..."
echo ""

# Parallel arrays: product codes, policy keys, human-readable labels.
PRODUCT_CODES=("PRODUCT_SP"   "PRODUCT_SPLM")
POLICY_KEYS=("spPolicy"       "splmPolicy")
PRODUCT_LABELS=("StellarProtect" "StellarProtect Legacy Mode")

for idx in 0 1; do
    PRODUCT_CODE="${PRODUCT_CODES[$idx]}"
    POLICY_KEY="${POLICY_KEYS[$idx]}"
    PRODUCT_LABEL="${PRODUCT_LABELS[$idx]}"

    echo "  --- ${PRODUCT_LABEL} (${PRODUCT_CODE}) ---"

    # GET current policy.
    echo "  [API] Reading current policy ..."
    POLICY_RESP=$(api_request_allow_404 "GET" "/api/v1/policy/global/${PRODUCT_CODE}")

    if [[ -z "$POLICY_RESP" ]]; then
        echo "  [SKIP] No global policy found for ${PRODUCT_LABEL} -- skipping."
        echo ""
        continue
    fi

    EXISTING_JSON=$(get_udso_list "$POLICY_RESP" "$POLICY_KEY")
    EXISTING_COUNT=$($PYTHON -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$EXISTING_JSON")
    echo "  [INFO] Existing UDSOs in policy: ${EXISTING_COUNT}"

    # Merge new hashes into the existing list.
    MERGE_RESULT=$(merge_iocs "$EXISTING_JSON" "$VALID_IOCS_JSON")
    ADDED=$(  $PYTHON -c "import json,sys; print(json.loads(sys.argv[1])['added'])"   "$MERGE_RESULT")
    SKIPPED=$($PYTHON -c "import json,sys; print(json.loads(sys.argv[1])['skipped'])" "$MERGE_RESULT")
    MERGED_JSON=$($PYTHON -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['merged']))" "$MERGE_RESULT")

    echo "  [INFO] New entries to add: ${ADDED}  |  Already present (skipped): ${SKIPPED}"

    if [[ "$ADDED" -eq 0 ]]; then
        echo "  [INFO] All hashes already exist in the policy -- no update needed."
        TOTAL_DUPES=$(( TOTAL_DUPES + SKIPPED ))
        echo ""
        continue
    fi

    TOTAL_ENTRIES=$($PYTHON -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$MERGED_JSON")
    echo "  [API] Writing updated policy (${TOTAL_ENTRIES} total UDSOs) ..."

    if put_global_policy "$POLICY_KEY" "$MERGED_JSON"; then
        echo "  [OK]  Policy updated successfully."
        TOTAL_ADDED=$(( TOTAL_ADDED + ADDED ))
        TOTAL_DUPES=$(( TOTAL_DUPES + SKIPPED ))
    else
        echo "  [FAIL] Could not write policy." >&2
        TOTAL_FAILED=$(( TOTAL_FAILED + ADDED ))
    fi

    echo ""
done


# ==============================================================================
# SECTION 8 - SUMMARY
# ==============================================================================

echo ""
echo "=============================================================="
echo "  Import Summary"
echo "--------------------------------------------------------------"
echo "  CSV file         : ${CSV_PATH}"
echo "  IOCs in CSV      : ${VALID_COUNT}"
echo "  Added            : ${TOTAL_ADDED}"
[[ $TOTAL_DUPES  -gt 0 ]] && echo "  Already present  : ${TOTAL_DUPES}"
[[ $SKIPPED_MD5  -gt 0 ]] && echo "  Skipped (MD5)    : ${SKIPPED_MD5}"
[[ $SKIPPED_BAD  -gt 0 ]] && echo "  Skipped (invalid): ${SKIPPED_BAD}"
[[ $TOTAL_FAILED -gt 0 ]] && echo "  Failed           : ${TOTAL_FAILED}"
echo "--------------------------------------------------------------"
echo "  NOTE: BLOCK/LOG action is a policy-level setting in the"
echo "  StellarOne console, not configurable per individual hash."
echo "=============================================================="
echo ""

if [[ "$TOTAL_FAILED" -gt 0 ]]; then
    exit 1
fi
