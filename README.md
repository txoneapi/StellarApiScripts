# Stellar_copyAgentPolicy

Scripts (PowerShell, Python, Bash) that copy the security policy from one **TXOne StellarOne** agent group to another via the StellarOne REST API.

## What it does

- Finds the source group by name and reads its policy (supports StellarProtect, StellarProtect Legacy Mode, and Linux agents)
- Creates the destination group automatically if it does not exist
- Applies the copied policy to the destination group
- Handles pagination, SSL self-signed certificates, and policy inheritance automatically

## Quick start

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

## Setup

1. Copy `stellarOne_example.conf` to `StellarOne.conf`
2. Fill in your StellarOne server URL and API key
3. Run the script of your choice

## Known limitation

Agent passwords are **not copied**. The StellarOne API never exposes password values — they must be set manually on the destination group after running the script. See [Stellar_CopyGroupPolicy.md](Stellar_CopyGroupPolicy.md) for full details.

## Files

| File | Description |
|------|-------------|
| `Stellar_CopyGroupPolicy.ps1` | PowerShell 5.1 script |
| `Stellar_CopyGroupPolicy.py` | Python 3 script |
| `Stellar_CopyGroupPolicy.sh` | Bash script |
| `Stellar_CopyGroupPolicy.md` | Full documentation |
| `Stellar_CopyGroupPolicy.pdf` | PDF version of the documentation |
| `stellarOne_example.conf` | Template — copy to `StellarOne.conf` and fill in your values |
| `StellarCopyGroupPolicy.prd.md` | Original requirements |
