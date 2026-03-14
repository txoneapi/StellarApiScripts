# Stellar_ExportAgents

**Created:** 2026-03-14

Scripts (PowerShell, Python, Bash) that export every managed agent from a **TXOne StellarOne** server to a CSV file via the StellarOne REST API.

StellarOne organises agents into a group tree of arbitrary depth — for example, `All > Region-West > SiteA > Building-3 > Production-Line-4`. When you need to work with this inventory outside of StellarOne (in a spreadsheet, a CMDB, a report, or a downstream automation), you need a flat file that still carries the tree context. These scripts produce exactly that: one CSV row per agent, with enough structure to slice, filter, and pivot the data in any direction.

---

## Step-by-Step: What happens when you run a script

| Step | What the script does |
|------|----------------------|
| **1** | Reads the StellarOne server address and API key from `StellarOne.conf`. |
| **2** | Establishes a secure connection to the StellarOne server (bypasses self-signed certificate warnings). |
| **3** | Downloads the **complete list of all agent groups** from StellarOne (handles multi-page results automatically). |
| **4** | Downloads the **complete list of all agents** from StellarOne (also paginated). |
| **5** | For each agent, **walks the group tree upward** from the agent's direct group to the root, collecting group names along the way, then reverses the path to produce a `[root, ..., leaf]` list. |
| **6** | Writes a CSV file with one row per agent, placing each level of the group path in its own column. |
| **7** | Prints a summary: total agents, online/offline count, maximum nesting depth, output file path. |

---

## CSV format design

This section explains the column layout in detail and the reasoning behind each decision.

### Column overview

A typical row (for an agent nested four levels deep) looks like this:

```
Hostname  , IP            , Online , DirectGroup     , All , L2          , L3      , L4              , FullPath
server-42 , 192.168.10.42 , Yes    , Production-Line , All , Region-West , Site-A  , Production-Line , All > Region-West > Site-A > Production-Line
```

### Fixed columns: Hostname, IP, Online

These three columns are always first and always have the same meaning. They cover the most common lookup questions: "what is this machine?", "how do I reach it?", and "is it alive?".

### Why is DirectGroup a fixed, early column?

`DirectGroup` always contains the name of the agent's immediate parent group — the innermost group, the leaf of the path. It is also the value that appears in the last tree column (L4 in the example above), so technically it is redundant.

It is kept as a separate fixed column for two practical reasons:

1. **You do not need to know the depth of the tree to filter by immediate group.** If you want to see every agent in "Production-Line", you apply one filter on the `DirectGroup` column — regardless of whether agents in that group are at depth 2 or depth 10.

2. **Sorting by DirectGroup groups all members of the same leaf group together**, making the CSV easy to scan visually without having to identify which "L" column is the relevant one for a given agent.

### Why are the hierarchy columns top-down (All, L2, L3, ...)?

The tree columns are ordered from root to leaf rather than from leaf to root. This makes column-based filtering work naturally in Excel and other tools:

- Filter `All = All` selects every agent (trivially true — this column is always "All").
- Filter `L2 = Region-West` selects every agent anywhere under Region-West, **at any depth**. You do not need to know whether those agents are at L3, L4, or L5; they all appear because their L2 is "Region-West".
- Filter `L2 = Region-West` AND `L3 = Site-A` narrows to a specific sub-site.
- Filter `DirectGroup = Production-Line` selects only agents whose immediate parent is "Production-Line", excluding any sub-groups under that name.

Filtering works top-down because all agents under a given node share the same value in that node's column. A bottom-up layout would not have this property.

### Why does the "All" root have its own column, even though every row has the same value?

The root group named "All" is always included as its own column for two reasons:

- **The tree is complete.** A tree that starts at L2 would be confusing — you would have to know that L2 is actually the second level of a four-level hierarchy. Starting at "All" makes it clear where the top is.
- **Pivoting is consistent.** When you copy the CSV into a pivot table, each level of the tree is a field you can drag into the row or column area. If the root were missing, the pivot structure would not match the actual tree.

### Why is FullPath included?

`FullPath` contains the complete group path as a single human-readable string, for example:

```
All > Region-West > Site-A > Production-Line
```

It is provided because:

- It is the most **readable** representation of where an agent lives. A row with `L3 = Site-A` and `L4 = Production-Line` is less immediately understandable than `All > Region-West > Site-A > Production-Line`.
- It is useful for **VLOOKUP / XLOOKUP** scenarios where you want to match agents by their complete path string rather than by individual level columns.
- It makes the CSV **self-contained** — you can read the file without needing to mentally reconstruct the path from multiple columns.

### How to use the CSV effectively in Excel

| Goal | How to do it |
|------|-------------|
| See all agents under a top-level region | Apply an AutoFilter on `L2`, select the region name |
| See all agents under a specific sub-site | Filter `L2 = Region` AND `L3 = Site` |
| See only agents directly in a specific group | Filter `DirectGroup = GroupName` |
| See all online agents | Filter `Online = Yes` |
| See all offline agents under a site | Filter `L2 = Site` AND `Online = No` |
| Count agents per top-level group | Pivot table with `L2` as rows, Count of `Hostname` as values |
| Find where a specific host lives | Sort or filter on `Hostname`, read `FullPath` column |
| Export agents from a deep sub-tree | Filter on the appropriate `L3`, `L4`, etc. column |

### Column count varies with environment depth

The number of tree columns (`All`, `L2`, `L3`, ...) is determined automatically at export time. The script finds the agent with the deepest group path and creates exactly that many columns. Agents at shallower depths leave the trailing columns empty.

This means the column count will differ between StellarOne environments. In a flat deployment with only one level under All, the CSV will have only an `All` column. In a deeply nested enterprise deployment, it may have `All` through `L6` or more.

---

## Prerequisites

All scripts require:

- **Network access** to the StellarOne management server
- **`StellarOne.conf`** in the repo root (see Setup below)

Additional prerequisites per script:

| Script | Runtime required |
|--------|-----------------|
| `Stellar_ExportAgents.ps1` | Windows PowerShell 5.1 (built into Windows 10 / Server 2016+) |
| `Stellar_ExportAgents.py`  | Python 3.6 or later — standard library only, no `pip install` needed |
| `Stellar_ExportAgents.sh`  | bash 4.0+, curl, and python3 (used as JSON processor and CSV writer) |

> **Tested on:** PowerShell 5.1 / Windows 10 · Python 3.12.2 / Windows MINGW64 · bash 5.2 / Windows MINGW64 and bash 5.1 / Ubuntu 22.04 — all against TXOne StellarOne 3.3.

---

## Setup

1. Copy `stellarOne_example.conf` to `StellarOne.conf` in the repo root
2. Fill in your StellarOne server URL and API key:

```
StellarOneURL="https://YOUR_STELLARONE_IP_OR_HOSTNAME"
ApiKey="YOUR_STELLARONE_API_KEY_HERE"
```

> **Security note:** `StellarOne.conf` contains sensitive credentials. Restrict access to this file to authorised administrators only. Never commit it to version control.

---

## How to run

### PowerShell

Export to an auto-named timestamped file in the script directory:
```powershell
.\Stellar_ExportAgents.ps1
```

Export to a specific path:
```powershell
.\Stellar_ExportAgents.ps1 -OutputFile "C:\Reports\agents.csv"
```

**Verbose output** (shows every API call):
```powershell
.\Stellar_ExportAgents.ps1 -Verbose
```

### Python

Export to an auto-named timestamped file:
```bash
python Stellar_ExportAgents.py
```

Export to a specific path:
```bash
python Stellar_ExportAgents.py C:\Reports\agents.csv
```

### Bash

Export to an auto-named timestamped file:
```bash
bash Stellar_ExportAgents.sh
```

Export to a specific path:
```bash
bash Stellar_ExportAgents.sh /tmp/agents.csv
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| Output file path | No | Where to write the CSV. If omitted, a timestamped file is created in the script directory. |

---

## StellarOne API calls used

### 1. List all groups
```
GET  /api/v1/groups?limit=100&page=<n>&pageToken=<token>
```
Returns one page of agent groups. The scripts keep requesting the next page (using the `pageToken` returned by each response) until all groups have been retrieved. This technique is called **pagination**.

Each group record includes:
- `groupUuid` — the group's unique identifier
- `name` — the display name
- `parentGroupUuid` — the UUID of the parent group (empty/null for the root "All" group)

### 2. List all agents
```
GET  /api/v1/agents?limit=100&page=<n>&pageToken=<token>
```
Returns one page of managed agents. The scripts paginate the same way as with groups.

Each agent record includes:
- `hostname` — the computer/device hostname
- `ipAddress` — the agent's IP address
- `agentOnlineStatus` — boolean: `true` if currently connected
- `groupUuid` — the UUID of the group this agent belongs to
- `agentUuid` — the agent's unique identifier

---

## Troubleshooting

| Problem | Likely cause | Solution |
|---------|-------------|----------|
| `Could not connect to https://...` | Wrong server address or firewall blocking port 443 | Verify the URL in `StellarOne.conf` and network connectivity |
| `API call failed - HTTP 401` | API key is wrong or expired | Generate a new API key in StellarOne and update `StellarOne.conf` |
| `API call failed - HTTP 403` | API key does not have read permission for agents or groups | Ask your StellarOne administrator to check the API key's scope |
| `Could not read the StellarOne server URL` | `StellarOne.conf` has wrong format | Ensure the file contains `StellarOneURL="https://..."` and `ApiKey="..."` |
| CSV opens with garbled characters in Excel | UTF-8 encoding not detected correctly | Python and Bash versions write a UTF-8 BOM automatically. For the PowerShell version, open via **Data > From Text/CSV** and select **UTF-8 with BOM** |
| `env: bash\r: No such file or directory` | Script downloaded on Windows has CRLF line endings | Run: `sed -i 's/\r//' Stellar_ExportAgents.sh` |
| All agents show `(unknown)` for groups | API returned groups with missing `groupUuid` fields | Verify the API key has permission to list groups; check with `GET /api/v1/groups` manually |
| CSV has only `All` and no L2+ columns | All agents are direct children of the root group | This is correct — the column count matches the actual tree depth |
| Output file path contains spaces (Windows) | Shell quoting issue | Wrap the path in double quotes: `bash Stellar_ExportAgents.sh "/c/My Reports/agents.csv"` |

---

## Files

```
StellarApiScripts/
├── stellarOne_example.conf            ← config template (copy to StellarOne.conf)
├── StellarOne.conf                    ← your credentials (gitignored, never committed)
├── Stellar_ExportAgents.md            ← this file
├── Stellar_ExportAgents.pdf           ← PDF version of this documentation
├── Stellar_ExportAgents.ps1           ← PowerShell 5.1 script
├── Stellar_ExportAgents.py            ← Python 3 script
└── Stellar_ExportAgents.sh            ← Bash script
```
