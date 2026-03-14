#!/usr/bin/env python3
# ==============================================================================
# FILE      : Stellar_ExportAgents.py
# CREATED   : 2026-03-14
# PURPOSE   : Exports all agents from StellarOne to a CSV file that reflects
#             the full group tree structure, with one column per hierarchy level.
# ==============================================================================
"""
SYNOPSIS
    Exports every managed agent from StellarOne to a CSV file.

DESCRIPTION
    This script is the Python equivalent of Stellar_ExportAgents.ps1.
    It connects to a TXOne StellarOne management server, downloads every
    managed agent and every agent group, and writes a CSV file where each
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

    Why this layout?
      See Stellar_ExportAgents.md for a full explanation of the design
      decisions behind the CSV format.

    API endpoints used:
      GET /api/v1/groups?limit=100&page=N&pageToken=T  - List all groups
      GET /api/v1/agents?limit=100&page=N&pageToken=T  - List all agents

USAGE
    python Stellar_ExportAgents.py [output_path]

    output_path  Optional.  Full path (or filename) for the CSV file.
                 Default: StellarOne_Agents_YYYYMMDD_HHMMSS.csv in the
                 same folder as this script.

PREREQUISITES
    - Python 3.6 or later  (standard library only -- no pip install required)
    - StellarOne.conf  in the same folder as this script
    - Network access to the StellarOne management server
"""

import sys
import os
import re
import csv
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
import datetime


# ==============================================================================
# SECTION 1 - COMMAND-LINE ARGUMENTS
# ==============================================================================
# This script accepts one optional argument:
#   argv[1] -- the output CSV file path (default: auto-generated in script dir)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

if len(sys.argv) > 2:
    print("Usage  : python Stellar_ExportAgents.py [output_path]")
    print("Example: python Stellar_ExportAgents.py C:\\Reports\\agents.csv")
    sys.exit(1)

if len(sys.argv) == 2:
    OUTPUT_FILE = sys.argv[1]
else:
    # Auto-generate a timestamped filename in the script directory.
    # Using a timestamp prevents accidentally overwriting a previous export.
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT_FILE = os.path.join(SCRIPT_DIR, f"StellarOne_Agents_{timestamp}.csv")


# ==============================================================================
# SECTION 2 - READ CONFIGURATION FILE
# ==============================================================================
# Rather than hard-coding the server address and API key directly in this
# script (which would be a security risk if the script is shared), we read
# them from a single configuration file that lives alongside the script.
#
#   StellarOne.conf  ->  contains the URL and the API authentication key
#
# os.path.abspath(__file__) gives the full path to this script regardless of
# which directory it is run from.  dirname() strips the filename, leaving
# just the folder path.

CONF_PATH = os.path.join(SCRIPT_DIR, "StellarOne.conf")

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
print("  StellarOne - Export Agents  (Python)")
print("=" * 62)
print(f"  Server           : {BASE_URL}")
print(f"  API key (first 8): {key_preview}...")
print(f"  Output file      : {OUTPUT_FILE}")
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


def api_request(method, endpoint, body=None):
    """
    Central function that sends any HTTP request to StellarOne and returns
    the parsed JSON response as a Python dictionary.

    Why have one shared function?
      Using a single wrapper ensures that every API call uses the same server
      URL, headers, and error-handling logic.  If something needs to change
      (e.g. adding a new header), you only change it in one place.

    Parameters:
      method    -- "GET", "POST", or "PUT"
      endpoint  -- URL path, e.g. "/api/v1/agents"
      body      -- Optional dict that becomes the JSON request body

    Returns:
      Parsed JSON as a Python dict.
    """
    url  = BASE_URL + endpoint
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=REQUEST_HEADERS, method=method)

    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}

    except urllib.error.HTTPError as exc:
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
      A list of group dicts, each containing at minimum:
        groupUuid       -- unique identifier for the group
        name            -- display name
        parentGroupUuid -- UUID of the parent group (None/empty for the root)
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


def get_all_agents():
    """
    Returns a complete list of every managed agent in StellarOne.

    Uses the same pagination technique as get_all_groups():
      - Request up to 100 agents per page.
      - Follow the pageToken until the API returns no more pages.

    Returns:
      A list of agent dicts, each containing at minimum:
        hostname          -- the computer/device hostname
        ipAddress         -- the agent's IP address
        agentOnlineStatus -- boolean: True if the agent is currently online
        groupUuid         -- UUID of the group this agent belongs to
        agentUuid         -- unique identifier for the agent
    """
    all_agents  = []
    page_token  = None
    page_number = 1
    page_size   = 100

    while True:
        print(f"  [API] Fetching agent list - page {page_number} ...")

        query = f"?limit={page_size}&page={page_number}"
        if page_token:
            query += "&pageToken=" + urllib.parse.quote(page_token, safe="")

        response = api_request("GET", f"/api/v1/agents{query}")

        agents = response.get("agents") or []
        all_agents.extend(agents)

        page_token = (response.get("pagination") or {}).get("pageToken") or ""
        if not page_token:
            break

        page_number += 1

    print(f"  [INFO] Found {len(all_agents)} agent(s) in StellarOne.")
    return all_agents


def build_group_map(all_groups):
    """
    Converts a flat list of group dicts into a dictionary keyed by groupUuid.

    Why build a map?
      The agent data only tells us the groupUuid of the agent's direct parent.
      To walk up the tree (e.g. find the grandparent, great-grandparent, etc.)
      we need to quickly look up any group by its UUID.  A dictionary gives us
      O(1) lookup time instead of scanning the list every time.

    Returns:
      { groupUuid: group_dict, ... }
    """
    return {g["groupUuid"]: g for g in all_groups if "groupUuid" in g}


def resolve_path(group_uuid, group_map):
    """
    Walks the group tree upward from the given group UUID to the root,
    collecting group names along the way, then reverses the result so the
    path reads from root (All) down to the direct group.

    Example:
      Given this tree:   All > SiteA > Production > Line-1
      Starting at Line-1's UUID, this function:
        1. Adds "Line-1"
        2. Follows parentGroupUuid to Production, adds "Production"
        3. Follows parentGroupUuid to SiteA, adds "SiteA"
        4. Follows parentGroupUuid to All, adds "All"
        5. All has no parentGroupUuid -> stops
        6. Reverses: ["All", "SiteA", "Production", "Line-1"]

    Safety:
      A visited-set prevents infinite loops in case the API returns a
      malformed tree with a circular parent reference.

    Parameters:
      group_uuid -- UUID of the agent's direct group
      group_map  -- { uuid: group_dict } from build_group_map()

    Returns:
      A list of group name strings from root to leaf, e.g.:
        ["All", "SiteA", "Production", "Line-1"]
      Returns ["(unknown)"] if the group UUID is not in the map.
    """
    if group_uuid not in group_map:
        return ["(unknown)"]

    path    = []
    visited = set()
    current_uuid = group_uuid

    while current_uuid and current_uuid not in visited:
        visited.add(current_uuid)
        group = group_map.get(current_uuid)
        if group is None:
            break
        path.append(group.get("name", "(unnamed)"))
        current_uuid = group.get("parentGroupUuid") or ""

    # path is currently [leaf, ..., root]; reverse to get [root, ..., leaf]
    path.reverse()
    return path


# ==============================================================================
# SECTION 6 - MAIN WORKFLOW
# ==============================================================================

# -- STEP 1: Load the complete group list --------------------------------------
# We need the full group tree so we can resolve each agent's ancestry.
# Groups are identified by UUID in the agent records; we need names and parents.
print("[STEP 1/4] Retrieving all agent groups from StellarOne ...")
try:
    all_groups = get_all_groups()
except StellarAPIError as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
print()


# -- STEP 2: Load the complete agent list --------------------------------------
print("[STEP 2/4] Retrieving all agents from StellarOne ...")
try:
    all_agents = get_all_agents()
except StellarAPIError as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
print()


# -- STEP 3: Build the group lookup map and resolve every agent's path --------
print("[STEP 3/4] Resolving group hierarchy for each agent ...")

# Convert the flat list of groups into a fast UUID-keyed dictionary.
group_map = build_group_map(all_groups)

# For each agent, walk the group tree to produce a list of names from
# root ("All") down to the agent's direct group.
resolved_agents = []

for agent in all_agents:
    group_uuid = agent.get("groupUuid") or ""
    path       = resolve_path(group_uuid, group_map)

    # DirectGroup is the last (innermost) element of the resolved path.
    # It is also the "Ln" column, but we duplicate it in a fixed-position
    # column at the front so it is always easy to find in the CSV.
    direct_group = path[-1] if path else "(unknown)"

    # Build a human-readable full path string for the last column.
    # Using " > " as the separator makes the hierarchy visually clear.
    full_path = " > ".join(path)

    # agentOnlineStatus is a boolean from the API.
    # We convert it to "Yes" / "No" for readability in Excel/CSV viewers.
    online_bool   = agent.get("agentOnlineStatus", False)
    online_string = "Yes" if online_bool else "No"

    resolved_agents.append({
        "hostname":     agent.get("hostname",  ""),
        "ip":           agent.get("ipAddress", ""),
        "online":       online_string,
        "direct_group": direct_group,
        "path":         path,        # list: ["All", "SiteA", ...]
        "full_path":    full_path,
    })

# Find the maximum path depth across all agents.
# This tells us how many "L" columns (All, L2, L3, ...) we need.
# Every agent row will have exactly this many tree columns; shorter paths
# leave the trailing columns empty.
if resolved_agents:
    max_depth = max(len(a["path"]) for a in resolved_agents)
else:
    max_depth = 1

print(f"  [INFO] Maximum group nesting depth: {max_depth}")
print()


# -- STEP 4: Write the CSV file ------------------------------------------------
print(f"[STEP 4/4] Writing CSV file: {OUTPUT_FILE}")

# Build the dynamic column header list.
#   Fixed columns : Hostname, IP, Online, DirectGroup
#   Tree columns  : "All" (always L1), then L2, L3, ... Ln
#   Trailing column: FullPath
#
# Why name the first tree column "All" instead of "L1"?
#   In StellarOne the root of the entire group tree is always named "All".
#   Naming the column "All" makes it immediately obvious what it represents.
#   Every row in this column will contain the string "All", making it a useful
#   visual anchor when you open the file in Excel.
tree_headers = ["All"] + [f"L{i}" for i in range(2, max_depth + 1)]
fieldnames   = ["Hostname", "IP", "Online", "DirectGroup"] + tree_headers + ["FullPath"]

try:
    # newline="" is required by the Python csv module to prevent extra blank
    # lines being inserted on Windows (where the default line ending is CRLF
    # and the csv writer adds its own CR).
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as csv_file:
        # utf-8-sig writes a UTF-8 BOM (Byte Order Mark) at the start of the
        # file.  Excel on Windows uses the BOM to detect UTF-8 encoding; without
        # it, special characters in hostnames may appear garbled when opening
        # the file by double-clicking in Windows Explorer.

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for agent in resolved_agents:
            path = agent["path"]

            # Start with the fixed columns.
            row = {
                "Hostname":    agent["hostname"],
                "IP":          agent["ip"],
                "Online":      agent["online"],
                "DirectGroup": agent["direct_group"],
            }

            # Fill in the tree columns.  path[0] goes under "All", path[1]
            # under "L2", etc.  If the path is shorter than max_depth, the
            # remaining tree columns are left as empty strings.
            for idx, header in enumerate(tree_headers):
                row[header] = path[idx] if idx < len(path) else ""

            row["FullPath"] = agent["full_path"]

            writer.writerow(row)

    print(f"  [OK]  CSV written: {len(resolved_agents)} agent(s) exported.")

except OSError as exc:
    print(f"ERROR: Could not write output file '{OUTPUT_FILE}': {exc}")
    sys.exit(1)


# ==============================================================================
# SECTION 7 - SUMMARY
# ==============================================================================

print()
print("=" * 62)
print("  Agent Export Summary")
print("-" * 62)
print(f"  Total agents exported : {len(resolved_agents)}")
online_count  = sum(1 for a in resolved_agents if a["online"] == "Yes")
offline_count = len(resolved_agents) - online_count
print(f"  Online                : {online_count}")
print(f"  Offline               : {offline_count}")
print(f"  Max group depth       : {max_depth}")
print(f"  CSV columns           : {len(fieldnames)}")
print("-" * 62)
print(f"  Output file           : {OUTPUT_FILE}")
print("=" * 62)
print()
