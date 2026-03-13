#!/usr/bin/env python3
# ==============================================================================
# FILE      : Stellar_CopyGroupPolicy.py
# CREATED   : 2026-03-14 00:01:44
# PURPOSE   : Copies the security policy from one StellarOne agent group to
#             another, creating the destination group if it does not yet exist.
# ==============================================================================
"""
SYNOPSIS
    Copies the security policy from a StellarOne source agent group to a
    destination agent group.

DESCRIPTION
    This script is the Python equivalent of Stellar_CopyGroupPolicy.ps1.
    It automates the same administrative task in TXOne StellarOne: taking the
    security configuration (policy) that is already set up on one group of
    managed agents and applying it to another group.

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

USAGE
    python Stellar_CopyGroupPolicy.py <SourceAgentGroup> <DestinationAgentGroup>

PREREQUISITES
    - Python 3.6 or later  (standard library only -- no pip install required)
    - StellarOne.conf  in the same folder as this script
    - Network access to the StellarOne management server
"""

import sys
import os
import re
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse


# ==============================================================================
# SECTION 1 - COMMAND-LINE ARGUMENTS
# ==============================================================================
# This script expects exactly two positional arguments:
#   argv[1] -- the name of the source group to copy FROM
#   argv[2] -- the name of the destination group to copy TO

def usage_and_exit():
    print("Usage  : python Stellar_CopyGroupPolicy.py <SourceAgentGroup> <DestinationAgentGroup>")
    print("Example: python Stellar_CopyGroupPolicy.py \"Production-Line-A\" \"Production-Line-B\"")
    sys.exit(1)

if len(sys.argv) != 3:
    usage_and_exit()

SOURCE_GROUP_NAME = sys.argv[1]
DEST_GROUP_NAME   = sys.argv[2]


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILES
# ==============================================================================
# Rather than hard-coding the server address and API key directly in this
# script (which would be a security risk if the script is shared), we read
# them from two separate files that live alongside the script.
#
#   StellarOne.conf  ->  contains the URL of the StellarOne management server
#   secrets.txt      ->  contains the API key used to authenticate every request

# os.path.abspath(__file__) gives the full path to this script regardless of
# which directory it is run from.  dirname() then strips the filename, leaving
# just the folder path.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH  = os.path.join(SCRIPT_DIR, "StellarOne.conf")

if not os.path.isfile(CONF_PATH):
    print(f"ERROR: Required configuration file not found: {CONF_PATH}")
    print("Please copy stellarOne_example.conf to StellarOne.conf and fill in your values.")
    sys.exit(1)

# Parse StellarOne.conf  -- expected format:
#   StellarOneURL="https://x.x.x.x"
#   ApiKey="<long hex string>"
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

print()
print("=" * 62)
print("  StellarOne - Copy Group Policy  (Python)")
print("=" * 62)
print(f"  Server           : {BASE_URL}")
print(f"  API key (first 8): {key_preview}...")
print(f"  Source group     : {SOURCE_GROUP_NAME}")
print(f"  Destination group: {DEST_GROUP_NAME}")
print("=" * 62)
print()


# ==============================================================================
# SECTION 3 - SSL CERTIFICATE HANDLING
# ==============================================================================
# StellarOne ships with a self-signed TLS certificate.  By default Python
# refuses to connect to servers whose certificate was not issued by a trusted
# Certificate Authority (CA) -- just like a browser shows a warning for unknown
# HTTPS sites.
#
# ssl.create_default_context() creates an SSL context.  Setting check_hostname
# to False and verify_mode to CERT_NONE tells Python to skip the certificate
# check for this session.  This is acceptable on a private management network
# but should NOT be used in internet-facing or security-sensitive environments.

SSL_CONTEXT                = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode    = ssl.CERT_NONE


# ==============================================================================
# SECTION 4 - DEFINE THE COMMON REQUEST HEADERS
# ==============================================================================
# Every HTTP request sent to StellarOne must carry an Authorization header
# containing the API key.  Think of it like a keycard: you must present it
# each time you enter a restricted area.
#
# The Content-Type and Accept headers tell the server that we are sending and
# expecting data in JSON format (a lightweight text-based data format).

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
    Central function that sends any HTTP request to StellarOne and returns
    the parsed JSON response as a Python dictionary.

    Why have one shared function?
      Using a single wrapper ensures that every API call uses the same server
      URL, headers, and error-handling logic.  If something needs to change
      (e.g. adding a new header), you only change it in one place.

    Parameters:
      method     -- "GET", "POST", or "PUT"
      endpoint   -- URL path, e.g. "/api/v1/groups"
      body       -- Optional dict that becomes the JSON request body
      allow_404  -- If True, returns None on HTTP 404 instead of raising

    Returns:
      Parsed JSON as a Python dict, or None if allow_404=True and HTTP 404.
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
        # Try to extract a human-readable message from the JSON error body.
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


def get_all_groups():
    """
    Returns a complete list of every agent group in StellarOne.

    Why is pagination needed?
      StellarOne returns results in "pages" -- like a book -- instead of
      sending all records at once.  Each page contains up to 100 groups.  At
      the end of each page the API provides a "page token" (like a bookmark)
      that lets us request the next page.  We keep requesting pages until the
      API stops providing a token, meaning we have reached the last page.

    Returns:
      A list of group dicts.
    """
    all_groups  = []
    page_token  = None
    page_number = 1
    page_size   = 100   # Request 100 groups per page (API maximum)

    while True:
        print(f"  [API] Fetching group list - page {page_number} ...")

        # Build the query string.  The API requires page >= 1, so we always
        # include it.  On subsequent pages we also send the pageToken returned
        # by the previous response (acts as a bookmark for the next page).
        query = f"?limit={page_size}&page={page_number}"
        if page_token:
            query += "&pageToken=" + urllib.parse.quote(page_token, safe="")

        response = api_request("GET", f"/api/v1/groups{query}")

        groups = response.get("groups") or []
        all_groups.extend(groups)

        # Move to the next page if the API provided a token; otherwise we are done.
        page_token = (response.get("pagination") or {}).get("pageToken") or ""
        if not page_token:
            break

        page_number += 1

    print(f"  [INFO] Found {len(all_groups)} group(s) in StellarOne.")
    return all_groups


def find_group_by_name(groups, name):
    """
    Searches a list of group dicts for one whose 'name' field exactly
    matches the requested name (case-sensitive).

    Returns:
      The matching group dict, or None if not found.
    """
    for group in groups:
        if group.get("name") == name:
            return group
    return None


def create_group(name, parent_group_uuid):
    """
    Creates a brand-new agent group in StellarOne under a given parent.
    The API requires parentGroupUuid -- all groups must have a parent.
    We use the source group's parent so the new group is created as a
    sibling of the source group (same level in the hierarchy).

    Returns:
      The newly created group dict (includes the new UUID).
    """
    print(f"  [API] Creating new group '{name}' under parent UUID {parent_group_uuid} ...")
    body     = {"name": name, "parentGroupUuid": parent_group_uuid}
    response = api_request("POST", "/api/v1/groups", body=body)
    new_uuid = (response.get("group") or {}).get("groupUuid", "?")
    print(f"  [OK]  Group '{name}' created  |  UUID = {new_uuid}")
    return response.get("group") or {}


def get_group_policy(group_uuid, product_code):
    """
    Retrieves the security policy for a group and a specific product.

    Why specify a product?
      A single StellarOne group can contain agents running different products:
        PRODUCT_SP    - StellarProtect (modern Windows agent)
        PRODUCT_SPLM  - StellarProtect Legacy Mode (older Windows agent)
        PRODUCT_LINUX - StellarProtect for Linux
      Each product has its own independent policy, so you must specify which
      one you want to retrieve.

    Returns:
      The policy dict, or None if no policy exists for that product (normal).
    """
    return api_request(
        "GET",
        f"/api/v1/policy/groups/{group_uuid}/product/{product_code}",
        allow_404=True,
    )


def set_policy_inheritance(group_uuid, mode):
    """
    Switches a group between inherited and customised policy mode.

    Why is this needed?
      When a new group is created in StellarOne it defaults to
      POLICY_INHERITANCE_INHERITED, meaning it simply copies its parent's
      policy and cannot have its own independent policy.  Before we can write
      a custom policy to the destination group we must switch it to
      POLICY_INHERITANCE_CUSTOMIZED.
    """
    api_request("PUT", f"/api/v1/groups/{group_uuid}", body={"policyInheritance": mode})


def remove_password_fields(policy):
    """
    Strips the 'passwords' sub-object from a retrieved policy before
    re-applying it to a different group.

    Why is this needed?
      When you GET a policy from StellarOne the password fields are returned as
      empty strings (the server never exposes real password values over the API
      for security reasons).  If you then PUT those empty strings back, the API
      rejects them because passwords must be at least 8 characters long.

      Solution: remove the passwords block entirely before sending.  Because
      the UpdateGroupPolicy endpoint uses replace-on-presence semantics,
      omitting the passwords block means the destination group keeps whatever
      password it already has.

    Parameters:
      policy -- the policy dict returned by get_group_policy()

    Returns:
      The same dict with the 'passwords' key removed from any sub-policy.
    """
    for policy_type in ("spPolicy", "splmPolicy", "linuxPolicy"):
        inner = policy.get(policy_type)
        if isinstance(inner, dict) and "passwords" in inner:
            del inner["passwords"]
    return policy


def apply_policy(group_uuid, policy):
    """
    Applies (writes) a security policy to a destination group.

    How the update works (replace-on-presence semantics):
      The StellarOne API uses a smart update strategy:
      - If you send a policy block (e.g. spPolicy), the server REPLACES that
        block on the destination group.
      - If you do NOT send a block, the server leaves it unchanged.
      This means we can safely update one product's policy without disturbing
      the policies for other products in the same group.
    """
    api_request("PUT", f"/api/v1/policy/groups/{group_uuid}", body={"policy": policy})


# ==============================================================================
# SECTION 6 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
# We fetch every group first so we can search by name.  StellarOne groups are
# identified internally by UUID (like "a1b2c3d4-..."), but humans use names.
print("[STEP 1/5] Retrieving all agent groups from StellarOne ...")
try:
    all_groups = get_all_groups()
except StellarAPIError as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
print()


# -- STEP 2: Verify the Source group exists ------------------------------------
print(f"[STEP 2/5] Locating source group '{SOURCE_GROUP_NAME}' ...")
source_group = find_group_by_name(all_groups, SOURCE_GROUP_NAME)

if source_group is None:
    available = "\n".join(f"  - {g.get('name', '?')}" for g in all_groups)
    print(f"ERROR: Source group '{SOURCE_GROUP_NAME}' was NOT found in StellarOne.")
    print("Please verify the group name (it is case-sensitive) and try again.")
    print(f"Available groups:\n{available}")
    sys.exit(1)

src_uuid = source_group.get("groupUuid", "?")
print(f"  [OK]  Source group found  |  UUID = {src_uuid}")
print()


# -- STEP 3: Find or create the Destination group ------------------------------
print(f"[STEP 3/5] Locating destination group '{DEST_GROUP_NAME}' ...")
dest_group = find_group_by_name(all_groups, DEST_GROUP_NAME)

if dest_group is None:
    print(f"  [INFO] Group '{DEST_GROUP_NAME}' does not exist yet - it will be created.")
    parent_uuid = source_group.get("parentGroupUuid")
    if not parent_uuid:
        print(f"ERROR: Source group '{SOURCE_GROUP_NAME}' has no parentGroupUuid.")
        print("Please create the destination group manually and re-run the script.")
        sys.exit(1)
    try:
        dest_group = create_group(DEST_GROUP_NAME, parent_uuid)
    except StellarAPIError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
else:
    dst_uuid = dest_group.get("groupUuid", "?")
    print(f"  [OK]  Destination group found  |  UUID = {dst_uuid}")

print()


# -- STEP 4: Retrieve the policy from the Source group -------------------------
# A group can have agents of different product types (SP, SPLM, Linux).
# We must copy the policy for each product the source group uses.
print(f"[STEP 4/5] Retrieving policy/policies from source group '{SOURCE_GROUP_NAME}' ...")

products_to_try = ["PRODUCT_SP", "PRODUCT_SPLM", "PRODUCT_LINUX"]

# Optimization: if the source group advertises its product codes, only query those.
source_products = source_group.get("productCodes") or []
filtered = [p for p in source_products if p != "PRODUCT_UNSPECIFIED"]
if filtered:
    products_to_try = filtered
    print(f"  [INFO] Source group uses product(s): {', '.join(products_to_try)}")

policies_to_apply = []

for product_code in products_to_try:
    print(f"  [API] Querying policy for product '{product_code}' ...")
    try:
        policy_data = get_group_policy(source_group["groupUuid"], product_code)
    except StellarAPIError as exc:
        print(f"  [WARN] Error querying '{product_code}': {exc}")
        continue

    if policy_data is not None:
        print(f"  [OK]  Policy found for '{product_code}'.")
        policies_to_apply.append({"product_code": product_code, "policy_data": policy_data})
    else:
        print(f"  [SKIP] No policy configured for '{product_code}' in source group.")

if not policies_to_apply:
    print(f"WARNING: No policies were found on source group '{SOURCE_GROUP_NAME}'.")
    print("There is nothing to copy. The script will now exit.")
    sys.exit(0)

print()


# -- STEP 5: Apply each policy to the Destination group -----------------------
policy_count = len(policies_to_apply)
print(f"[STEP 5/5] Applying {policy_count} policy/policies to destination group '{DEST_GROUP_NAME}' ...")

# Before writing any policy, switch the destination group to customised mode.
# New groups default to INHERITED, which means the API will reject any attempt
# to write a policy directly to them.
print("  [API] Setting destination group to customised policy mode ...")
try:
    set_policy_inheritance(dest_group["groupUuid"], "POLICY_INHERITANCE_CUSTOMIZED")
    print("  [OK]  Policy inheritance set to CUSTOMIZED.")
except StellarAPIError as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)

success_count = 0
fail_count    = 0

for entry in policies_to_apply:
    product_code = entry["product_code"]
    print(f"  [API] Applying '{product_code}' policy ...")
    try:
        # Strip password fields -- the GET response returns them as empty strings
        # and the API will reject empty passwords on PUT.  Omitting the passwords
        # block leaves the destination group's existing passwords unchanged.
        clean_policy = remove_password_fields(entry["policy_data"])
        apply_policy(dest_group["groupUuid"], clean_policy)
        print(f"  [OK]  '{product_code}' policy applied successfully.")
        success_count += 1
    except StellarAPIError as exc:
        print(f"  [FAIL] Failed to apply '{product_code}' policy: {exc}")
        fail_count += 1


# ==============================================================================
# SECTION 7 - SUMMARY
# ==============================================================================

print()
print("=" * 62)
print("  Policy Copy Summary")
print("-" * 62)
print(f"  From (source)      : {SOURCE_GROUP_NAME}")
print(f"  Source UUID        : {source_group.get('groupUuid', '?')}")
print(f"  To (destination)   : {DEST_GROUP_NAME}")
print(f"  Destination UUID   : {dest_group.get('groupUuid', '?')}")
print("-" * 62)
print(f"  Policies applied   : {success_count}")
if fail_count:
    print(f"  Policies failed    : {fail_count}")
print("=" * 62)
print()

if fail_count:
    sys.exit(1)
