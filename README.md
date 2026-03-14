# StellarApiScripts

PowerShell, Python, and Bash scripts that automate administrative tasks on **TXOne StellarOne** via its REST API.

---

## Scripts

| Script | What it does | Docs |
|--------|-------------|------|
| [Stellar_CopyGroupPolicy](./Stellar_CopyGroupPolicy.md) | Copies a security policy from one agent group to another | [md](./Stellar_CopyGroupPolicy.md) · [pdf](./Stellar_CopyGroupPolicy.pdf) |
| [Stellar_ExportAgents](./Stellar_ExportAgents.md) | Exports all agents to a CSV file reflecting the group tree structure | [md](./Stellar_ExportAgents.md) · [pdf](./Stellar_ExportAgents.pdf) |

---

## Shared setup

All scripts read credentials from `StellarOne.conf` in the repo root. Copy the template and fill in your values:

```
cp stellarOne_example.conf StellarOne.conf
```

Then edit `StellarOne.conf`:

```
StellarOneURL="https://YOUR_STELLARONE_IP_OR_HOSTNAME"
ApiKey="YOUR_STELLARONE_API_KEY_HERE"
```

> **Security note:** `StellarOne.conf` contains sensitive credentials. It is listed in `.gitignore` and must never be committed.

---

## Repo layout

```
StellarApiScripts/
├── README.md                          ← this file
├── stellarOne_example.conf            ← config template (safe to commit)
├── StellarOne.conf                    ← your credentials (gitignored, never committed)
│
├── Stellar_CopyGroupPolicy.md         ← documentation
├── Stellar_CopyGroupPolicy.pdf        ← documentation (PDF)
├── Stellar_CopyGroupPolicy.ps1        ← PowerShell 5.1
├── Stellar_CopyGroupPolicy.py         ← Python 3
├── Stellar_CopyGroupPolicy.sh         ← Bash
│
├── Stellar_ExportAgents.md            ← documentation
├── Stellar_ExportAgents.pdf           ← documentation (PDF)
├── Stellar_ExportAgents.ps1           ← PowerShell 5.1
├── Stellar_ExportAgents.py            ← Python 3
└── Stellar_ExportAgents.sh            ← Bash
```
