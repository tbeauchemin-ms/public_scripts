<#
.SYNOPSIS
    Checks if Blob containers in specified Storage Accounts are protected by Azure Backup.

.DESCRIPTION
    This script retrieves all Storage Accounts and checks each Blob container to see if it is protected by Azure Backup in any Backup Vault.
    It can logg the results to a local CSV file or sends them to Azure Monitor Log Ingestion API based on the specified parameters.

.PARAMETER AuthMethod
    Authentication method to use. Allowed values are "Interactive" and "ManagedIdentity". Default is "Interactive".

.PARAMETER LogMethod
    Method of logging results. Allowed values are "Disabled", "AzureMonitor", and "LocalFile". Default is "Disabled".
    Logging using LocalFile is not suppored when running in Azure Automation.

.PARAMETER LocalLogFilePath
    Path to the local log file where results will be saved if LogMethod is set to "LocalFile". Default is "BlobContainerBackupLog.csv".

.PARAMETER LogApiAuthMethod
    Authentication method for Log Ingestion API. Currently only "ManagedIdentity" is supported.

.PARAMETER LogApiDceUri
    Data Collection Endpoint URI for Log Ingestion API. Required if LogMethod is set to "AzureMonitor".

.PARAMETER LogApiDcrImmutableId
    Immutable ID of the Data Collection Rule for Log Ingestion API. Required if LogMethod is set to "AzureMonitor".

.PARAMETER LogApiDcrStreamName
    Stream name for the Data Collection Rule for Log Ingestion API. Required if LogMethod is set to "AzureMonitor".

.NOTES
    Requires Az.Accounts, Az.Storage, and Az.DataProtection modules.
    The identity used to run the script requires permissions to read storage accounts and backup vaults.
    The location where the script is run must be able to access the Storage Account on the public or private endpoint.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Interactive", "ManagedIdentity")]
    [string] $AuthMethod = "Interactive",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Disabled", "AzureMonitor", "LocalFile")]
    [string] $LogMethod = "Disabled",

    [Parameter(Mandatory=$false)]
    [string] $LocalLogFilePath = "BlobContainerBackupLog.csv",

    [Parameter(Mandatory=$false)]
    [ValidateSet("ManagedIdentity")]
    [string] $LogApiAuthMethod = "ManagedIdentity",

    [Parameter(Mandatory=$false)]
    [string] $LogApiDceUri,

    [Parameter(Mandatory=$false)]
    [string] $LogApiDcrImmutableId,

    [Parameter(Mandatory=$false)]
    [string] $LogApiDcrStreamName
)

# Ensure Az modules are imported
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Storage -ErrorAction Stop
Import-Module Az.DataProtection -ErrorAction Stop

## Logging Helper Functions

# Helper: Get authentication token for Log Ingestion API
function Get-LogIngestionApiAuthToken {
    [OutputType([System.Security.SecureString])]
    param ()

    try {
        $secureAccessToken = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com/" -AsSecureString -ErrorAction Stop
        if ($null -eq $secureAccessToken -or [string]::IsNullOrWhiteSpace($secureAccessToken.Token)) {
            Write-Error "Access token is null or empty."
            return $null
        }
        Write-Information "Successfully obtained access token for Log Ingestion API."
        return $secureAccessToken.Token
    }
    catch {
        Write-Error "Failed to get access token for Log Ingestion API: $($_.Exception)"
        return $null
    }
}

# Helper: Send data to Log Ingestion API
function Send-LogIngestionApiData {
    param(
        [Parameter(Mandatory=$true)]
        [array] $LogEntries
    )

    try {
        $secureAuthToken = Get-LogIngestionApiAuthToken
        if ($null -eq $secureAuthToken -or $secureAuthToken -isnot [System.Security.SecureString]) {
            throw "Failed to obtain authentication token for Log Ingestion API."
        }

        $uri = "$($LogApiDceUri)/dataCollectionRules/$($LogApiDcrImmutableId)/streams/Custom-$($LogApiDcrStreamName)_CL?api-version=2023-01-01"
        $headers = @{
            "Authorization" = "Bearer $(ConvertFrom-SecureString -SecureString $secureAuthToken -AsPlainText)"
            "Content-Type" = "application/json"
        }
        $body = $LogEntries | ConvertTo-Json -Depth 10

        Write-Information "Sending data to Log Ingestion API at $uri..."
        Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to send data to Log Ingestion API: $($_.Exception)"
        return $null
    }

}

# Helper: Write all log entries to local CSV file at once
function Write-LocalLogEntries {
    param(
        [Parameter(Mandatory=$true)]
        [array] $LogEntries,
        [Parameter(Mandatory=$true)]
        [string] $FilePath
    )

    # Prepare CSV header if logging to LocalFile
    if (-not (Test-Path $LocalLogFilePath)) {
        "" | Out-File -FilePath $LocalLogFilePath # Create file if not exists
        $header = "StorageAccountResourceId,SubscriptionId,ResourceGroupName,StorageAccountName,ContainerName,IsProtected,BackupVaultResourceId,BackupPolicyResourceId"
        $header | Out-File -FilePath $LocalLogFilePath -Encoding utf8
    }

    $selectProps = 'StorageAccountResourceId','SubscriptionId','ResourceGroupName','StorageAccountName','ContainerName','IsProtected','BackupVaultResourceId','BackupPolicyResourceId'
    $LogEntries | Select-Object $selectProps | Export-Csv -Path $FilePath -Encoding utf8 -Append -Force

}

### Storage Account and Backup Vault Helper Functions

# Helper: Get all storage accounts in scope
function Get-TargetStorageAccounts {
    try {
        $allAccounts = Get-AzStorageAccount -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve Storage Accounts: $($_.Exception)"
    }
    return $allAccounts | Sort-Object -Property Id -Unique
}

# Helper: Get all Backup Vaults in the current subscription, with ResourceGroupName
function Get-AllBackupVaults {
    try {
        $vaults = Get-AzDataProtectionBackupVault -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve Backup Vaults: $($_.Exception)"
        continue
    }
    foreach ($vault in $vaults) {
        if (-not $vault.PSObject.Properties["ResourceGroupName"]) {
            $azRes = Get-AzResource -ResourceId $vault.Id -ErrorAction SilentlyContinue
            if ($azRes) {
                $vault | Add-Member -NotePropertyName ResourceGroupName -NotePropertyValue $azRes.ResourceGroupName -Force
            }
        }
    }
    return $vaults
}

# Helper: Check if a blob container is protected by Azure Backup in any Backup Vault
function Test-BlobContainerBackup {
    param(
        [string] $StorageAccountId,
        [string] $ContainerName
    )
    $vaults = Get-AllBackupVaults
    foreach ($vault in $vaults) {
        try {
            $backupInstances = Get-AzDataProtectionBackupInstance `
                -ResourceGroupName $vault.ResourceGroupName `
                -VaultName $vault.Name `
                -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to retrieve backup instances for vault $($vault.Name): $($_.Exception)"
            continue
        }
        if ($backupInstances) {
            foreach ($instance in $backupInstances) {
                $dsInfo = $instance.Property.DataSourceInfo
                if ($dsInfo.Type -eq "Microsoft.Storage/storageAccounts/blobServices" -and $dsInfo.ResourceId -eq $StorageAccountId) {
                    $containerList = $instance.Property.PolicyInfo.PolicyParameter.BackupDatasourceParametersList.ContainersList
                    if ($containerList -contains $ContainerName) {
                        # Return extra info for logging
                        return @{
                            IsProtected = $true
                            BackupVaultResourceId = $vault.Id
                            BackupPolicyResourceId = $instance.Property.PolicyInfo.PolicyId
                        }
                    }
                }
            }
        }
    }
    return @{
        IsProtected = $false
        BackupVaultResourceId = $null
        BackupPolicyResourceId = $null
    }
}

### Main Script Execution

Write-Output "Starting Blob Container Backup Check..."

Write-Debug "Parameters:"
Write-Debug "  AuthMethod: $($AuthMethod)"
Write-Debug "  LogMethod: $($LogMethod)"
Write-Debug "  LocalLogFilePath: $($LocalLogFilePath)"
Write-Debug "  LogApiAuthMethod: $($LogApiAuthMethod)"
Write-Debug "  LogApiDceUri: $($LogApiDceUri)"
Write-Debug "  LogApiDcrImmutableId: $($LogApiDcrImmutableId)"
Write-Debug "  LogApiDcrStreamName: $($LogApiDcrStreamName)"

# Connect to Azure based on the authentication method specified in the AuthMethod parameter
try {
    if ($AuthMethod -eq "ManagedIdentity") {
        Write-Information "Connecting to Azure using Managed Identity..."
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    else {
        Write-Information "Connecting to Azure using Interactive login..."
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception)"
    throw $_.Exception
}

# Main logic
Write-Information "Retrieving Storage Accounts..."
$storageAccounts = Get-TargetStorageAccounts

# Summary counters
$totalStorageAccounts = 0
$totalContainers = 0
$totalProtected = 0
$totalUnprotected = 0

# Collect log entries if LocalFile logging is enabled
$allLogEntries = @()

if ($storageAccounts -and $storageAccounts.Count -gt 0) {
    Write-Information " - Found $($storageAccounts.Count) Storage Accounts."
    foreach ($account in $storageAccounts) {
        $totalStorageAccounts++
        Write-Output "Checking Storage Account: $($account.StorageAccountName) in Resource Group: $($account.ResourceGroupName)"
        $ctx = New-AzStorageContext -StorageAccountName $account.StorageAccountName -UseConnectedAccount
        try {
            $containers = Get-AzStorageContainer -Context $ctx -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to get containers for Storage Account $($account.StorageAccountName): $($_.Exception)"
            continue
        }
        $containerCount = 0
        $protectedCount = 0
        $unprotectedCount = 0
        foreach ($container in $containers) {
            $containerCount++
            $result = Test-BlobContainerBackup -StorageAccountId $account.Id -ContainerName $container.Name
            $isProtected = $result.IsProtected
            if ($isProtected) {
                $protectedCount++
                Write-Output "  [PROTECTED]     Container: $($container.Name)"
            }
            else {
                $unprotectedCount++
                Write-Output "  [NOT PROTECTED] Container: $($container.Name)"
            }
            if ($LogMethod -ne "Disabled") {
                $logEntry = [PSCustomObject]@{
                    TimeGenerated            = (Get-Date).ToUniversalTime().ToString("o")
                    StorageAccountResourceId = $account.Id
                    SubscriptionId           = $account.Id.Split("/")[2]
                    ResourceGroupName        = $account.ResourceGroupName
                    StorageAccountName       = $account.StorageAccountName
                    ContainerName            = $container.Name
                    IsProtected              = [bool]$isProtected
                    BackupVaultResourceId    = $result.BackupVaultResourceId
                    BackupPolicyResourceId   = $result.BackupPolicyResourceId
                }
                $allLogEntries += $logEntry
            }
        }
        $totalContainers += $containerCount
        $totalProtected += $protectedCount
        $totalUnprotected += $unprotectedCount
        Write-Output "  Storage Account Summary: $containerCount containers, $protectedCount protected, $unprotectedCount unprotected."
    }
    # Write all log entries at once if LocalFile logging is enabled
    if ($LogMethod -eq "LocalFile" -and $allLogEntries.Count -gt 0) {
        Write-Information "Writing log entries to Local File $($LocalLogFilePath)..."
        Write-LocalLogEntries -LogEntries $allLogEntries -FilePath $LocalLogFilePath
    }
    if ($LogMethod -eq "AzureMonitor" -and $allLogEntries.Count -gt 0) {
        Write-Information "Sending log entries to Azure Monitor Log Ingestion API..."
        Send-LogIngestionApiData -LogEntries $allLogEntries
    }
    Write-Output ""
    Write-Output "================== OVERALL SUMMARY =================="
    Write-Output "Storage Accounts searched: $totalStorageAccounts"
    Write-Output "Total containers found:    $totalContainers"
    Write-Output "Containers protected:      $totalProtected"
    Write-Output "Containers unprotected:    $totalUnprotected"
    Write-Output "====================================================="
}
else {
    Write-Output "No Storage Accounts found."
}
