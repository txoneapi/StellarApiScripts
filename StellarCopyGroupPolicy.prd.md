# StellarCopyGroupPolicy - Product Requirements

**Created:** 2026-03-14 00:01:44

## Overview

Create scripts in **PowerShell**, **Python**, and **Bash** that:
1. Accept 2 parameters: `SourceAgentGroup` and `DestinationAgentGroup`
2. Extract the policy of the StellarOne `SourceAgentGroup`
3. Apply it to the `DestinationAgentGroup`
4. Create the destination group automatically if it does not exist

## Deliverables

| File | Language | Description |
|------|----------|-------------|
| `Stellar_CopyGroupPolicy.ps1` | PowerShell 5.1 | Windows-native script |
| `Stellar_CopyGroupPolicy.py`  | Python 3       | Cross-platform script |
| `Stellar_CopyGroupPolicy.sh`  | Bash           | Linux / macOS / Git Bash script |
| `Stellar_CopyGroupPolicy.md`  | Markdown       | Full user documentation |
| `Stellar_CopyGroupPolicy.pdf` | PDF            | PDF version of the documentation |

## Tested Versions

| Script | Runtime | Version | Platform |
|--------|---------|---------|----------|
| `Stellar_CopyGroupPolicy.ps1` | PowerShell | 5.1.17763.6532 | Windows 10 / Server 2016+ |
| `Stellar_CopyGroupPolicy.py`  | Python | 3.12.2 | Windows (MINGW64) |
| `Stellar_CopyGroupPolicy.sh`  | bash | 5.2.37 (MINGW64) | Windows / Git Bash |
| `Stellar_CopyGroupPolicy.sh`  | bash | 5.1 (target) | Ubuntu 22.04 / Linux |

All three scripts were tested against a live **TXOne StellarOne 3.3.1392** server.

## Configuration Files

Both configuration files must be in the same folder as the scripts:

| File | Purpose | Format |
|------|---------|--------|
| `StellarOne.conf` | StellarOne server URL | `StellarOneURL="https://YOUR_IP"` |
| `secrets.txt` | API authentication key | `ApiKey="YOUR_API_KEY"` |

Template files `stellarOne_example.conf` and `secrets_example.txt` are provided.

## Usage

```powershell
# PowerShell
.\Stellar_CopyGroupPolicy.ps1 -SourceAgentGroup "GroupA" -DestinationAgentGroup "GroupB"
```

```bash
# Python (cross-platform)
python Stellar_CopyGroupPolicy.py "GroupA" "GroupB"
```

```bash
# Bash (Linux / macOS / Git Bash)
bash Stellar_CopyGroupPolicy.sh "GroupA" "GroupB"
```

## Prerequisites per Script

### PowerShell
- Windows PowerShell 5.1 (built into Windows 10 / Server 2016+)
- Network access to the StellarOne server

### Python
- Python 3.6 or later
- Standard library only — no `pip install` required
- Network access to the StellarOne server

### Bash
- bash 4.0 or later
- `curl` (standard on Linux/macOS; included with Git for Windows)
- `python3` or `python` (used as JSON processor; standard on Linux/macOS)
- Network access to the StellarOne server

## Context

The output will be used as a training example showing how to use the StellarOne REST API.
All three scripts must be **descriptive and educational** so non-technical readers can learn from them:
- Section headers explaining what each part does
- Comments explaining *why*, not just *what*
- Clear step-by-step output messages

## General Instructions

1. Make an MD file (and PDF) that describes what the scripts do
2. Add the file creation date as a comment in every file
3. Ask for more details when needed; do not guess
4. Test every script against the live server before delivering
5. Never commit `secrets.txt` or `StellarOne.conf` to version control

## Known Limitations

- **Agent passwords are not copied.** The StellarOne API masks passwords as `"*"` and never
  returns the real value. The scripts remove the passwords block entirely before applying
  policies; the destination group keeps its own existing passwords.
  See `Stellar_CopyGroupPolicy.md` for the full explanation and manual workaround.
