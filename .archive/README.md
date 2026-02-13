# Archived Scripts

This directory contains scripts that have been superseded by newer implementations.
They are kept for reference but should not be used.

## bash-scripts/

| Script | Replaced By | Notes |
|--------|-------------|-------|
| `test-revocation.sh` | `./lab test` | Python CLI with better error handling |
| `validate-lab.sh` | `./lab validate` | Python CLI with JSON output support |
| `preflight-check.sh` | `./lab validate` | Integrated into validate pre-flight checks |

## Migration Date

Archived: 2024-02 (during Python CLI migration)

## Restoring

If needed, scripts can be restored:
```bash
mv .archive/bash-scripts/test-revocation.sh ./
```
