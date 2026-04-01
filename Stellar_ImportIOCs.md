# Stellar_ImportIOCs

**Created:** 2026-04-01

Scripts (PowerShell, Python, Bash) that import file-hash IOCs from a CSV file into **TXOne StellarOne** as User-Defined Suspicious Objects (UDSOs) via the StellarOne REST API.

In TXOne StellarOne, the global policy for each product type contains a list of User-Defined Suspicious Objects — file hashes that the agent should watch for on managed endpoints.  When a running file matches a hash in this list, StellarOne logs a detection event and can block execution.  These scripts automate loading a fresh IOC list into StellarOne in seconds, without touching the management console.

---

## Step-by-Step: What happens when you run a script

| Step | What the script does |
|------|----------------------|
| **1** | Reads the StellarOne server address and API key from `StellarOne.conf`. |
| **2** | Parses the IOC CSV file, skipping blank lines, comment lines, and the optional header row. |
| **3** | Auto-detects the hash type for each row from the hash length (SHA-1 = 40 hex chars, SHA-256 = 64 hex chars). |
| **4** | Skips MD5 hashes (32 hex chars) with a warning — StellarOne's UDSO API does not support MD5. |
| **5** | For each product type (StellarProtect and StellarProtect Legacy Mode), **GETs** the current global policy. |
| **6** | Merges the new hashes into the existing UDSO list — existing hashes are preserved and duplicates are skipped. |
| **7** | **PUTs** the updated policy back to StellarOne. |
| **8** | Prints a summary: how many hashes were added, already present, skipped, or failed. |

---

## Prerequisites

All scripts require:

- **Network access** to the StellarOne management server
- **`StellarOne.conf`** in the same folder as the script (see Setup below)
- **`IOCs.csv`** — the IOC list to import (see CSV Format below)

Additional prerequisites per script:

| Script | Runtime required |
|--------|-----------------|
| `Stellar_ImportIOCs.ps1` | Windows PowerShell 5.1 (built into Windows 10 / Server 2016+) |
| `Stellar_ImportIOCs.py`  | Python 3.6 or later — standard library only, no `pip install` needed |
| `Stellar_ImportIOCs.sh`  | bash 4.0+, curl, and python3 (used as JSON processor) |

> **Tested on:** PowerShell 5.1 / Windows 10 · Python 3.12 / Windows MINGW64 · bash 5.2 / Windows MINGW64 and bash 5.1 / Ubuntu 22.04 — all against TXOne StellarOne 3.3.1392.

---

## Setup

1. Copy `stellarOne_example.conf` to `StellarOne.conf`
2. Fill in your StellarOne server URL and API key:

```
StellarOneURL="https://YOUR_STELLARONE_IP_OR_HOSTNAME"
ApiKey="YOUR_STELLARONE_API_KEY_HERE"
```

3. Create your `IOCs.csv` file (or copy from `IOCs_example.csv` and replace the hashes with real IOCs).

> **Security note:** `StellarOne.conf` contains sensitive credentials. Restrict access to this file to authorised administrators only. Never commit it to version control.

---

## CSV Format

```
# Lines starting with '#' are treated as comments and ignored.
# Blank lines are also ignored.
# An optional header row (first cell = "hash") is automatically skipped.
# The action column is optional and is accepted for documentation only.
# NOTE: MD5 hashes (32 hex chars) are NOT supported and will be skipped.
#
hash,description,action
935200fdb9410116dea80d66b1349d3fca9f4d8b,Ransomware dropper - ticket #1234 (SHA-1),BLOCK
e46b6e54f91e82d8ec5853764ed8d226912de90a,Dropper variant x64 (SHA-1),BLOCK
906895fbd6244c6d1cfc42a72e0e30100a237e8da61e374d8319a53cb29f81a0,Suspicious payload - log only (SHA-256),LOG
```

| Column | Required | Description |
|--------|----------|-------------|
| `hash` | Yes | SHA-1 (40 hex chars) or SHA-256 (64 hex chars). MD5 (32 hex chars) is **not** supported by StellarOne's UDSO API and will be skipped. |
| `description` | Yes | Free-text note stored alongside the hash in StellarOne |
| `action` | No | `BLOCK` or `LOG`. **Accepted for documentation only — not sent to the API.** StellarOne does not support per-hash actions; the action is a policy-level setting configured in the StellarOne console. |

Rows with an unrecognised hash length or non-hex characters are skipped with a warning — the rest of the file continues to import.

---

## How to run

```powershell
# PowerShell -- use the default IOCs.csv in the script folder
.\Stellar_ImportIOCs.ps1

# PowerShell -- pass an explicit path
.\Stellar_ImportIOCs.ps1 -CsvPath "C:\IOCs\campaign_xyz.csv"
```

```bash
# Python -- use the default IOCs.csv in the script folder
python Stellar_ImportIOCs.py

# Python -- pass an explicit path
python Stellar_ImportIOCs.py /path/to/my_iocs.csv
```

```bash
# Bash -- use the default IOCs.csv in the script folder
bash Stellar_ImportIOCs.sh

# Bash -- pass an explicit path
bash Stellar_ImportIOCs.sh /path/to/my_iocs.csv
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| CSV path  | No | Path to the IOC CSV file. Defaults to `IOCs.csv` in the script folder. |

---

## StellarOne API calls used

### 1 — Read the current global policy

```
GET /api/v1/policy/global/{product_code}
```

| `{product_code}` | Product |
|------------------|---------|
| `PRODUCT_SP`   | StellarProtect |
| `PRODUCT_SPLM` | StellarProtect Legacy Mode |

Returns the full global policy for that product type, including the existing `userDefinedSuspiciousObjects` list.

---

### 2 — Write the updated global policy

```
PUT /api/v1/policy/global
```

Only the `userDefinedSuspiciousObjects` block is sent in the request body.  All other policy settings are left untouched (replace-on-presence semantics).

**Request body structure:**

```json
{
  "policy": {
    "spPolicy": {
      "userDefinedSuspiciousObjects": {
        "list": [
          {
            "value": "<hash in lowercase>",
            "notes": "<description from CSV>",
            "type":  "TYPE_SHA1"
          },
          {
            "value": "<hash in lowercase>",
            "notes": "<description from CSV>",
            "type":  "TYPE_SHA256"
          }
        ]
      }
    }
  }
}
```

| Field | Value | Notes |
|-------|-------|-------|
| `value` | Hash value | Normalised to lowercase before sending |
| `notes` | Description from the CSV | Stored as a note in StellarOne |
| `type` | `TYPE_SHA1` or `TYPE_SHA256` | Auto-detected from hash length |

> **Note:** Use `splmPolicy` instead of `spPolicy` when updating the StellarProtect Legacy Mode policy.

---

## Known Limitations

- **MD5 hashes are not supported.** The StellarOne UDSO API only accepts SHA-1 and SHA-256.  MD5 rows in the CSV are skipped with a warning.
- **No per-hash BLOCK/LOG action.** StellarOne does not support configuring the action per individual hash.  The `action` column in the CSV is accepted for documentation purposes but is not sent to the API.  Configure the response action in the StellarOne console at the policy level.

---

## Troubleshooting

| Problem | Likely cause | Solution |
|---------|-------------|----------|
| `IOC file not found` | CSV file is missing or path is wrong | Check the file exists and re-run with an explicit path |
| `not a recognised SHA-1 or SHA-256 hash` | Hash has wrong length or contains non-hex characters | Fix the row in the CSV |
| `MD5 hash not supported` | 32-character hex hash detected | Replace MD5 hashes with SHA-1 or SHA-256 equivalents |
| `API call failed - HTTP 401` | API key is wrong or expired | Regenerate the key in StellarOne and update `StellarOne.conf` |
| `API call failed - HTTP 403` | API key lacks write permission | Ask your StellarOne administrator to grant the key write access |
| `Could not connect to ...` | Wrong server address or firewall blocking port 443 | Verify the URL in `StellarOne.conf` and network connectivity |
| `No global policy found for ...` | Product type has no global policy configured yet | Configure a global policy in the StellarOne console first |

---

## Files

```
StellarAPI/
  Stellar_ImportIOCs.ps1    <-- PowerShell 5.1 script
  Stellar_ImportIOCs.py     <-- Python 3 script
  Stellar_ImportIOCs.sh     <-- Bash script
  Stellar_ImportIOCs.md     <-- This documentation
  Stellar_ImportIOCs.pdf    <-- PDF version of this documentation
  IOCs.csv                  <-- Your IOC list  (keep this file private!)
  IOCs_example.csv          <-- Template -- copy to IOCs.csv and fill in real hashes
  StellarOne.conf           <-- Server URL + API key  (keep this file private!)
  stellarOne_example.conf   <-- Template -- copy to StellarOne.conf and fill in values
```
