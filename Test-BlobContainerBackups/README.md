# Test-BlobContainerBackups.ps1

The `Test-BlobContainerBackups.ps1` script checks whether blob containers in your Azure Storage Accounts are protected by Azure Backup. It provides a summary of protected and unprotected containers across all storage accounts in your current Azure context.

## Features

- Lists all storage accounts in your Azure subscription.
- Checks each blob container for Azure Backup protection.
- Supports authentication via interactive login or managed identity.
- Outputs a summary of protected and unprotected containers.

## Prerequisites

- Azure PowerShell modules:
  - Az.Accounts
  - Az.Storage
  - Az.DataProtection
- Sufficient permissions to read storage accounts and backup vaults.

## Parameters

| Name        | Type   | Description                                                                 | Default        |
|-------------|--------|-----------------------------------------------------------------------------|----------------|
| AuthMethod  | string | Authentication method: `Interactive` or `ManagedIdentity`                   | Interactive    |

## Usage

1. Install the required Azure PowerShell modules if not already installed.
2. Run the script in PowerShell:

```powershell
# For interactive login
[Test-BlobContainerBackups.ps1](http://_vscodecontentref_/0)

# For managed identity (e.g., in Azure Automation or VM with managed identity)
[Test-BlobContainerBackups.ps1](http://_vscodecontentref_/1) -AuthMethod ManagedIdentity
```

## Example Output

```
Starting Blob Container Backup Check...
Connecting to Azure using Interactive login...
Retrieving Storage Accounts...
 - Found 3 Storage Accounts.
Checking Storage Account: mystorageaccount in Resource Group: myresourcegroup
  [PROTECTED]     Container: backups
  [NOT PROTECTED] Container: logs
  -- Storage Account Summary: 2 containers, 1 protected, 1 unprotected.

================== OVERALL SUMMARY ==================
Storage Accounts searched: 3
Total containers found:    6
Containers protected:      2
Containers unprotected:    4
=====================================================
```