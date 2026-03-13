# Stellar_copyAgentPolicy

A PowerShell 5.1 script that copies the security policy from one **TXOne StellarOne** agent group to another via the StellarOne REST API.

## What it does

- Finds the source group by name and reads its policy (supports StellarProtect, StellarProtect Legacy Mode, and Linux agents)
- Creates the destination group automatically if it does not exist
- Applies the copied policy to the destination group
- Handles pagination, SSL self-signed certificates, and policy inheritance automatically

## Quick start

```powershell
.\Copy-StellarGroupPolicy.ps1 -SourceAgentGroup "GroupA" -DestinationAgentGroup "GroupB"
```

## Setup

1. Copy `stellarOne_example.conf` to `StellarOne.conf` and set your server URL
2. Copy `secrets_example.txt` to `secrets.txt` and set your StellarOne API key
3. Run the script from a PowerShell 5.1 window

## Known limitation

Agent passwords are **not copied**. The StellarOne API never exposes password values — they must be set manually on the destination group after running the script. See [Copy-StellarGroupPolicy.md](Copy-StellarGroupPolicy.md) for full details.

## Files

| File | Description |
|------|-------------|
| `Copy-StellarGroupPolicy.ps1` | The main script |
| `Copy-StellarGroupPolicy.md` | Full documentation |
| `Copy-StellarGroupPolicy.pdf` | PDF version of the documentation |
| `stellarOne_example.conf` | Template for server configuration |
| `secrets_example.txt` | Template for API credentials |
| `StellarCopyGroupPolicy.prd.md` | Original requirements |
