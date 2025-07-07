# Test-BlobContainerBackups

The `Test-BlobContainerBackups` script checks whether blob containers in your Azure Storage Accounts are protected by Azure Backup. It provides a summary of protected and unprotected containers across all storage accounts in your current Azure context.

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

| Name                 | Type         | Description                                                                                                   | Default        |
|----------------------|--------------|---------------------------------------------------------------------------------------------------------------|----------------|
| AuthMethod           | string       | Authentication method: `Interactive` or `ManagedIdentity`                                                     | Interactive    |
| LogMethod            | string       | Logging method: `Disabled`, `AzureMonitor`, or `LocalFile`                                                    | Disabled       |
| LocalLogFilePath     | string       | Path to the local log file (used if `LogMethod` is `LocalFile`)                                               | BlobContainerBackupLog.csv |
| LogApiAuthMethod     | string       | Authentication method for Log Ingestion API: `AppId` or `ManagedIdentity`                                     |                |
| LogApiTenantId       | string       | Azure AD tenant ID for Log Ingestion API authentication (required if `LogApiAuthMethod` is `AppId`)           |                |
| LogApiAppId          | string       | Azure AD application (client) ID for Log Ingestion API authentication (required if `LogApiAuthMethod` is `AppId`) |                |
| LogApiAppSecret      | securestring | Azure AD application secret for Log Ingestion API authentication (required if `LogApiAuthMethod` is `AppId`)  |                |
| LogApiDceUri         | string       | Data Collection Endpoint URI for Log Ingestion API (required if `LogMethod` is `AzureMonitor`)                |                |
| LogApiDcrImmutableId | string       | Immutable ID of the Data Collection Rule for Log Ingestion API (required if `LogMethod` is `AzureMonitor`)    |                |
| LogApiDcrStreamName  | string       | Stream name for the Data Collection Rule for Log Ingestion API (required if `LogMethod` is `AzureMonitor`)    |                |
| MessageLevel         | string       | Controls the verbosity of script output: `Debug`, `Verbose`, `Information`, `Warning`, or `Error`             | Information    |

## Usage

1. Install the required Azure PowerShell modules if not already installed.
2. Run the script in PowerShell:

```powershell
# For interactive login
Test-BlobContainerBackups

# For managed identity (e.g., in Azure Automation or VM with managed identity)
Test-BlobContainerBackups -AuthMethod ManagedIdentity

# To log results to a local CSV file
Test-BlobContainerBackups -LogMethod LocalFile -LocalLogFilePath "C:\temp\BlobBackupLog.csv"

# To send logs to Azure Monitor Log Ingestion API
Test-BlobContainerBackups -LogMethod AzureMonitor -LogApiAuthMethod ManagedIdentity -LogApiDceUri "<DCE URI>" -LogApiDcrImmutableId "<DCR Immutable ID>" -LogApiDcrStreamName "<Stream Name>"

# To control output verbosity (e.g., show debug messages)
Test-BlobContainerBackups -MessageLevel Debug

# To use AppId authentication for Log Ingestion API
Test-BlobContainerBackups -LogMethod AzureMonitor -LogApiAuthMethod AppId -LogApiTenantId "<TenantId>" -LogApiAppId "<AppId>" -LogApiAppSecret (ConvertTo-SecureString "<Secret>" -AsPlainText -Force) -LogApiDceUri "<DCE URI>" -LogApiDcrImmutableId "<DCR Immutable ID>" -LogApiDcrStreamName "<Stream Name>"
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