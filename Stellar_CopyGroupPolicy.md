# Stellar_CopyGroupPolicy.ps1

**Created:** 2026-03-13 00:00:00

---

## What does this script do?

This PowerShell script copies the security policy from one **StellarOne agent group** to another.

In TXOne StellarOne, every group of managed agents can have its own security policy — a set of rules that control what the agents are allowed to do (e.g., which programs can run, how they respond to threats). When you want a new group to use the same rules as an existing group, doing that manually through the console would be slow and error-prone. This script automates the entire process in seconds.

---

## Step-by-Step: What happens when you run the script

| Step | What the script does |
|------|----------------------|
| **1** | Reads the StellarOne server address and API authentication key from `StellarOne.conf`. |
| **2** | Establishes a secure connection to the StellarOne server (bypasses self-signed certificate warnings). |
| **3** | Downloads the **complete list of all agent groups** from StellarOne (handles multi-page results automatically). |
| **4** | Finds the **source group** by name. Stops with a clear error message if it does not exist. |
| **5** | Checks whether the **destination group** exists. **Creates it automatically** if it does not. |
| **6** | Retrieves the policy from the source group for **each product type** it uses (StellarProtect, StellarProtect Legacy Mode, Linux). |
| **7** | Applies each retrieved policy to the destination group. |
| **8** | Prints a summary showing what was copied and whether everything succeeded. |

---

## Prerequisites

Before running the script, make sure you have:

- **Windows PowerShell 5.1** (built into Windows 10 / Windows Server 2016 and later)
- **Network access** to the StellarOne management server
- **One configuration file** in the same folder as the script:

  | File | Purpose | Example content |
  |------|---------|-----------------|
  | `StellarOne.conf` | Server address and API key | `StellarOneURL="https://192.168.23.119"` |
  |                   |                            | `ApiKey="391113a9b449..."` |

  Copy `stellarOne_example.conf` to `StellarOne.conf` and fill in your values.

> **Security note:** `StellarOne.conf` contains sensitive credentials. Restrict access to this file to authorised administrators only. Never commit it to version control.

---

## How to run the script

Open a PowerShell window and run:

```powershell
.\Stellar_CopyGroupPolicy.ps1 -SourceAgentGroup "GroupA" -DestinationAgentGroup "GroupB"
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SourceAgentGroup` | Yes | The **exact name** of the group to copy the policy **from**. Case-sensitive. |
| `-DestinationAgentGroup` | Yes | The **exact name** of the group to copy the policy **to**. Will be created if it does not exist. |

### Examples

**Copy policy from "Production-Line-A" to "Production-Line-B":**
```powershell
.\Stellar_CopyGroupPolicy.ps1 -SourceAgentGroup "Production-Line-A" `
                               -DestinationAgentGroup "Production-Line-B"
```

**Verbose output (shows every API call being made):**
```powershell
.\Stellar_CopyGroupPolicy.ps1 -SourceAgentGroup "Production-Line-A" `
                               -DestinationAgentGroup "Production-Line-B" -Verbose
```

---

## StellarOne API calls used

This section explains the four API endpoints the script uses — useful for understanding how StellarOne's REST API works.

### 1. List all groups
```
GET  /api/v1/groups?limit=100&pageToken=<token>
```
Returns a page of agent groups. The script keeps requesting the next page (using the `pageToken` returned by each response) until all groups have been retrieved. This technique is called **pagination**.

### 2. Create a new group
```
POST /api/v1/groups
Body: { "name": "GroupB" }
```
Creates a brand-new group at the root level. The API responds with the new group's details, including its **UUID** (a unique identifier like `a1b2c3d4-1234-5678-...`).

### 3. Get a group's policy (per product)
```
GET  /api/v1/policy/groups/{group_uuid}/product/{product_code}
```
Retrieves the security policy for a specific product type. The `product_code` is one of:

| Code | Meaning |
|------|---------|
| `PRODUCT_SP` | StellarProtect (modern Windows agent) |
| `PRODUCT_SPLM` | StellarProtect Legacy Mode (older Windows agent) |
| `PRODUCT_LINUX` | StellarProtect for Linux |

A group can have agents of different types, so the script calls this endpoint once per product and collects all policies that exist.

### 4. Update a group's policy
```
PUT  /api/v1/policy/groups/{group_uuid}
Body: { "policy": { "spPolicy": { ... } } }
```
Applies a policy to the destination group. This endpoint uses **replace-on-presence** semantics:
- Only the policy blocks you include in the request body are changed.
- Any blocks you leave out remain exactly as they were.

This means it is safe to call this endpoint once per product without accidentally wiping out the other products' policies.

---

## What the script does NOT do

- It does **not** move agents between groups. Agents remain in their original groups.
- It does **not** delete or modify the source group.
- It does **not** copy agents or agent-specific (individual) policies — only the **group-level** policy is copied.
- It does **not** copy agent passwords (see Known Limitations below).

---

## Known Limitations

### Agent passwords are not copied

The StellarOne API never exposes actual password values. When you read a group policy that has passwords configured, the API returns a single `*` character as a masked placeholder — not the real password and not a hash. There is no API endpoint that returns the plaintext or hashed password.

What the API returns for the `passwords` block:

| Situation | `adminPass` / `userPass` value |
|---|---|
| Password is set | `"*"` (single asterisk — masked) |
| Password is not set | `""` (empty string) |

Because of this, the script **removes the passwords block entirely** before applying the policy to the destination group. The destination group will keep its own existing passwords (or the system default if it was just created).

This also affects the two boolean settings inside the same block:

| Setting | Copied? |
|---|---|
| `enableAdminPolicyCentralManaged` | **No** |
| `enableUserPolicyCentralManaged` | **No** |

These settings control whether StellarOne centrally manages the agent passwords and are meaningful policy settings. However, the API requires valid password strings to be present whenever the passwords block is sent — it is not possible to send the boolean flags alone. There is no workaround via the API.

**What you must do manually after running the script:**
Open the destination group in the StellarOne management console and configure:
1. The agent admin password
2. The agent user password
3. The "centrally managed" toggle for each (if applicable)

---

## Troubleshooting

| Problem | Likely cause | Solution |
|---------|-------------|----------|
| `Source group 'X' was NOT found` | Group name is misspelled or has different capitalisation | Check the exact name in the StellarOne console |
| `API call failed - HTTP 401` | API key is wrong or expired | Generate a new API key in StellarOne and update `StellarOne.conf` |
| `API call failed - HTTP 403` | API key does not have the required permissions | Ask your StellarOne administrator to check the API key's scope |
| `Could not read the StellarOne server URL` | `StellarOne.conf` has wrong format | Ensure the file contains `StellarOneURL="https://..."` and `ApiKey="..."` |
| SSL/TLS connection error | Wrong server address or firewall blocking port 443 | Verify the URL in `StellarOne.conf` and network connectivity |

---

## File overview

```
StellarAPI/
  Stellar_CopyGroupPolicy.ps1   <-- PowerShell script
  Stellar_CopyGroupPolicy.py    <-- Python script
  Stellar_CopyGroupPolicy.sh    <-- Bash script
  Stellar_CopyGroupPolicy.md    <-- This documentation file
  StellarOne.conf               <-- Server URL + API key  (keep this file private!)
  stellarOne_example.conf       <-- Template -- copy to StellarOne.conf and fill in values
```
