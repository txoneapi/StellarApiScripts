#!/usr/bin/env python3
# ==============================================================================
# FILE      : Stellar_ImportIOCs.py
# CREATED   : 2026-04-01
# PURPOSE   : Reads a list of file hashes (IOCs) from IOCs.csv and adds each
#             one as a User-Defined Suspicious Object (UDSO) in TXOne StellarOne.
# ==============================================================================
"""
SYNOPSIS
    Imports file-hash IOCs from a CSV file into StellarOne as User-Defined
    Suspicious Objects (UDSO).

DESCRIPTION
    The script reads IOCs.csv, which must contain one IOC per line in the
    format:

        <hash>,<description>

    For every row it merges the hash into the global policy's
    userDefinedSuspiciousObjects list for each active product type
    (StellarProtect and StellarProtect Legacy Mode).

    How it works:
      1. GET the current global policy for each product type.
      2. Merge the new hashes into the existing UDSO list
         (duplicates are detected by hash value and skipped).
      3. PUT the updated policy back.

    Supported hash types (StellarOne API limitation):
      SHA-1   -- 40 hex characters
      SHA-256 -- 64 hex characters
      MD5 is NOT supported by the StellarOne UDSO API.

    NOTE: StellarOne does not support a per-hash BLOCK/LOG action.
      The action is configured at the policy level in the StellarOne console,
      not per individual hash entry. The 'action' column in the CSV is
      accepted for documentation purposes but is not sent to the API.

    API endpoints used:
      GET /api/v1/policy/global/{product_code}  -- Read current global policy
      PUT /api/v1/policy/global                 -- Write updated global policy

USAGE
    python Stellar_ImportIOCs.py [<path-to-csv>]

    If no path is given the script looks for IOCs.csv in the same folder
    as the script itself.

PREREQUISITES
    - Python 3.6 or later  (standard library only -- no pip install required)
    - StellarOne.conf  in the same folder as this script
    - IOCs.csv         in the same folder (or pass a path as the first argument)
    - Network access to the StellarOne management server

CSV FORMAT
    # Lines starting with '#' are treated as comments and skipped.
    # Blank lines are also skipped.
    # The 'action' column is accepted but not used (API limitation).
    #
    # hash,description,action
    aabbcc1122334455667788990011223344556677,Some SHA-1 example,BLOCK
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4da11aad0b27eb18d7a1286d5,SHA-256 example,LOG
"""

import sys
import os
import re
import csv
import json
import ssl
import urllib.request
import urllib.error


# ==============================================================================
# SECTION 1 - COMMAND-LINE ARGUMENTS
# ==============================================================================

CSV_PATH_ARG = sys.argv[1] if len(sys.argv) >= 2 else None


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILES
# ==============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH  = os.path.join(SCRIPT_DIR, "StellarOne.conf")

if not os.path.isfile(CONF_PATH):
    print(f"ERROR: Required configuration file not found: {CONF_PATH}")
    print("Please copy stellarOne_example.conf to StellarOne.conf and fill in your values.")
    sys.exit(1)

with open(CONF_PATH, encoding="utf-8") as fh:
    conf_text = fh.read()

m = re.search(r'StellarOneURL="([^"]+)"', conf_text)
if not m:
    print(f"ERROR: Could not read the StellarOne server URL from: {CONF_PATH}")
    print('Expected a line like:  StellarOneURL="https://192.168.1.1"')
    sys.exit(1)
BASE_URL = m.group(1).rstrip("/")

m = re.search(r'ApiKey="([^"]+)"', conf_text)
if not m:
    print(f"ERROR: Could not read the API key from: {CONF_PATH}")
    print('Expected a line like:  ApiKey="abc123..."')
    sys.exit(1)
API_KEY     = m.group(1)
key_preview = API_KEY[:8] if len(API_KEY) >= 8 else API_KEY

CSV_PATH = CSV_PATH_ARG if CSV_PATH_ARG else os.path.join(SCRIPT_DIR, "IOCs.csv")

if not os.path.isfile(CSV_PATH):
    print(f"ERROR: IOC file not found: {CSV_PATH}")
    print("Create the file or pass its path as the first argument.")
    sys.exit(1)

print()
print("=" * 62)
print("  StellarOne - Import IOCs  (Python)")
print("=" * 62)
print(f"  Server           : {BASE_URL}")
print(f"  API key (first 8): {key_preview}...")
print(f"  IOC file         : {CSV_PATH}")
print("=" * 62)
print()


# ==============================================================================
# SECTION 3 - SSL CERTIFICATE HANDLING
# ==============================================================================

SSL_CONTEXT                = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode    = ssl.CERT_NONE


# ==============================================================================
# SECTION 4 - DEFINE THE COMMON REQUEST HEADERS
# ==============================================================================

REQUEST_HEADERS = {
    "Authorization": API_KEY,
    "Content-Type":  "application/json",
    "Accept":        "application/json",
}


# ==============================================================================
# SECTION 5 - HELPER FUNCTIONS
# ==============================================================================

class StellarAPIError(Exception):
    """Raised when a StellarOne API call returns an unexpected error."""
    pass


def api_request(method, endpoint, body=None, allow_404=False):
    """
    Sends an HTTP request to StellarOne and returns the parsed JSON response.

    Parameters:
      method     -- HTTP verb: "GET", "PUT"
      endpoint   -- URL path, e.g. "/api/v1/policy/global"
      body       -- Optional dict that will be JSON-encoded as the request body
      allow_404  -- If True, returns None on HTTP 404 instead of raising

    Returns:
      Parsed JSON as a Python dict (empty dict if the response body is empty).
    """
    url  = BASE_URL + endpoint
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=REQUEST_HEADERS, method=method)

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}

    except urllib.error.HTTPError as exc:
        if allow_404 and exc.code == 404:
            return None
        try:
            detail = json.dumps(json.loads(exc.read().decode("utf-8")), indent=2)
        except Exception:
            detail = str(exc)
        raise StellarAPIError(
            f"API call failed: {method} {endpoint}  |  HTTP {exc.code}  |  {detail}"
        ) from exc

    except urllib.error.URLError as exc:
        raise StellarAPIError(
            f"Could not connect to {url}: {exc.reason}"
        ) from exc


# Hash-length to StellarOne UDSO type mapping.
# NOTE: MD5 (32 chars) is NOT supported by the StellarOne UDSO API.
HASH_TYPE_MAP = {
    40: "TYPE_SHA1",
    64: "TYPE_SHA256",
}

HEX_CHARS = set("0123456789abcdefABCDEF")


def detect_hash_type(value):
    """
    Infers the hash algorithm from the length of the hash string.

    Returns:
      "TYPE_SHA1" or "TYPE_SHA256", or None if the value is not a supported hash.
      MD5 hashes (32 chars) return None -- not supported by StellarOne UDSO API.
    """
    stripped = value.strip()
    if not stripped:
        return None
    if not all(c in HEX_CHARS for c in stripped):
        return None
    return HASH_TYPE_MAP.get(len(stripped))


def get_global_policy(product_code):
    """
    Retrieves the current global policy for a given product type.

    Returns the policy dict, or None if no policy exists for that product.
    """
    return api_request(
        "GET",
        f"/api/v1/policy/global/{product_code}",
        allow_404=True,
    )


def extract_udso_list(policy_response, policy_key):
    """
    Extracts the existing UDSO list from a GET global policy response.

    Parameters:
      policy_response -- the dict returned by get_global_policy()
      policy_key      -- "spPolicy" or "splmPolicy"

    Returns:
      A list of existing UDSO dicts (may be empty).
    """
    if not policy_response:
        return []
    inner = policy_response.get(policy_key) or {}
    udso  = inner.get("userDefinedSuspiciousObjects") or {}
    return list(udso.get("list") or [])


def merge_iocs_into_list(existing_list, new_iocs):
    """
    Merges new IOC entries into the existing UDSO list.

    Duplicates are detected by comparing hash values (case-insensitive).
    Existing entries are preserved unchanged; only genuinely new hashes
    are appended.

    Parameters:
      existing_list -- list of UDSO dicts already in the policy
      new_iocs      -- list of (hash_value, description, hash_type) tuples

    Returns:
      (merged_list, added_count, skipped_count)
    """
    # Build a set of existing values for fast duplicate detection.
    existing_values = {entry.get("value", "").lower() for entry in existing_list}

    merged       = list(existing_list)
    added_count   = 0
    skipped_count = 0

    for hash_value, description, hash_type in new_iocs:
        normalised = hash_value.strip().lower()
        if normalised in existing_values:
            skipped_count += 1
        else:
            merged.append({
                "value": normalised,
                "notes": description.strip(),
                "type":  hash_type,
            })
            existing_values.add(normalised)
            added_count += 1

    return merged, added_count, skipped_count


def put_global_policy(policy_key, udso_list):
    """
    Writes the updated UDSO list back to the global policy for one product.

    Uses replace-on-presence semantics: only the userDefinedSuspiciousObjects
    block is sent, so all other policy settings are left unchanged.

    Parameters:
      policy_key -- "spPolicy" or "splmPolicy"
      udso_list  -- the complete (merged) list of UDSO dicts to store
    """
    body = {
        "policy": {
            policy_key: {
                "userDefinedSuspiciousObjects": {
                    "list": udso_list
                }
            }
        }
    }
    api_request("PUT", "/api/v1/policy/global", body=body)


# ==============================================================================
# SECTION 6 - PARSE THE CSV FILE
# ==============================================================================
# Supported layouts:
#   hash,description           -- 2 columns (action column optional)
#   hash,description,action    -- 3 columns (action logged but not sent to API)
#
# The StellarOne UDSO API does not support a per-hash action (BLOCK/LOG).
# The action is a policy-level setting configured in the StellarOne console.

print("[STEP 1/3] Reading IOCs from CSV ...")

ioc_rows = []
skipped_md5   = 0
skipped_bad   = 0

with open(CSV_PATH, newline="", encoding="utf-8") as fh:
    for line_no, raw_line in enumerate(fh, start=1):
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        row = next(csv.reader([stripped]))

        if len(row) < 2:
            print(f"  [WARN] Line {line_no}: expected at least 2 columns, got {len(row)} -- skipping.")
            skipped_bad += 1
            continue

        hash_val = row[0].strip()
        desc_val = row[1].strip()
        # action column is read for display only -- not sent to the API
        action_val = row[2].strip().upper() if len(row) >= 3 else "BLOCK"

        # Skip header row
        if hash_val.lower() == "hash":
            continue

        hash_type = detect_hash_type(hash_val)

        if hash_type is None:
            if len(hash_val) == 32 and all(c in HEX_CHARS for c in hash_val):
                print(f"  [SKIP] Line {line_no}: MD5 hash not supported by StellarOne UDSO API -- {hash_val}")
                skipped_md5 += 1
            else:
                print(f"  [SKIP] Line {line_no}: '{hash_val}' -- not a recognised SHA-1 or SHA-256 hash.")
                skipped_bad += 1
            continue

        ioc_rows.append((line_no, hash_val, desc_val, action_val, hash_type))

print(f"  [INFO] {len(ioc_rows)} valid IOC(s) ready to import.")
if skipped_md5:
    print(f"  [INFO] {skipped_md5} MD5 hash(es) skipped -- not supported by StellarOne UDSO API.")
if skipped_bad:
    print(f"  [INFO] {skipped_bad} row(s) skipped due to format errors.")
print()

if not ioc_rows:
    print("Nothing to import.  Verify that IOCs.csv contains SHA-1 or SHA-256 hashes.")
    sys.exit(0)

# Build the list of (hash_value, description, hash_type) tuples for merging.
iocs_to_merge = [(h, d, t) for (_, h, d, _, t) in ioc_rows]


# ==============================================================================
# SECTION 7 - MAIN WORKFLOW: MERGE IOCS INTO EACH PRODUCT POLICY
# ==============================================================================
# StellarOne stores UDSOs inside the global policy, once per product type.
# We update both StellarProtect (spPolicy) and StellarProtect Legacy Mode
# (splmPolicy) so that agents of both types receive the new hashes.
#
# Product codes used for the GET endpoint:
#   PRODUCT_SP   -> policy key: spPolicy
#   PRODUCT_SPLM -> policy key: splmPolicy

PRODUCTS = [
    ("PRODUCT_SP",   "spPolicy",   "StellarProtect"),
    ("PRODUCT_SPLM", "splmPolicy", "StellarProtect Legacy Mode"),
]

total_added   = 0
total_dupes   = 0
total_failed  = 0

print(f"[STEP 2/3] Merging {len(ioc_rows)} IOC(s) into global policy ...")
print()

for product_code, policy_key, product_label in PRODUCTS:
    print(f"  --- {product_label} ({product_code}) ---")

    # GET current policy
    print(f"  [API] Reading current policy ...")
    try:
        policy_resp = get_global_policy(product_code)
    except StellarAPIError as exc:
        print(f"  [FAIL] Could not read policy: {exc}")
        total_failed += len(ioc_rows)
        continue

    if policy_resp is None:
        print(f"  [SKIP] No global policy found for {product_label} -- skipping.")
        continue

    existing = extract_udso_list(policy_resp, policy_key)
    print(f"  [INFO] Existing UDSOs in policy: {len(existing)}")

    # Merge
    merged, added, dupes = merge_iocs_into_list(existing, iocs_to_merge)
    print(f"  [INFO] New entries to add: {added}  |  Already present (skipped): {dupes}")

    if added == 0:
        print(f"  [INFO] All hashes already exist in the policy -- no update needed.")
        total_dupes += dupes
        print()
        continue

    # PUT updated policy
    print(f"  [API] Writing updated policy ({len(merged)} total UDSOs) ...")
    try:
        put_global_policy(policy_key, merged)
        print(f"  [OK]  Policy updated successfully.")
        total_added  += added
        total_dupes  += dupes
    except StellarAPIError as exc:
        print(f"  [FAIL] Could not write policy: {exc}")
        total_failed += added

    print()


# ==============================================================================
# SECTION 8 - SUMMARY
# ==============================================================================

print()
print("=" * 62)
print("  Import Summary")
print("-" * 62)
print(f"  CSV file         : {CSV_PATH}")
print(f"  IOCs in CSV      : {len(ioc_rows)}")
print(f"  Added            : {total_added}")
if total_dupes:
    print(f"  Already present  : {total_dupes}")
if skipped_md5:
    print(f"  Skipped (MD5)    : {skipped_md5}")
if skipped_bad:
    print(f"  Skipped (invalid): {skipped_bad}")
if total_failed:
    print(f"  Failed           : {total_failed}")
print("=" * 62)
print()
print("  NOTE: BLOCK/LOG action is a policy-level setting in the")
print("  StellarOne console, not configurable per individual hash.")
print("=" * 62)
print()

if total_failed:
    sys.exit(1)
