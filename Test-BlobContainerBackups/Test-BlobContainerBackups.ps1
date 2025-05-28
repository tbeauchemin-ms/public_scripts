<#
.SYNOPSIS
    Checks if Blob containers in specified Storage Accounts are protected by Azure Backup.

.PARAMETER AuthMethod
    Authentication method to use. Allowed values are "Interactive" and "ManagedIdentity". Default is "Interactive".

.NOTES
    Requires Az.Accounts, Az.Storage, and Az.DataProtection modules.
    Identity used to run the script requires permissions to read storage accounts and backup vaults.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Interactive", "ManagedIdentity")]
    [string] $AuthMethod = "Interactive"
)

# Ensure Az modules are imported
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Storage -ErrorAction Stop
Import-Module Az.DataProtection -ErrorAction Stop

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
                        return $true
                    }
                }
            }
        }
    }
    return $false
}

Write-Output "Starting Blob Container Backup Check..."

# Connect to Azure based on the authentication method specified in the AuthMethod parameter
try {
    if ($AuthMethod -eq "ManagedIdentity") {
        Write-Output "Connecting to Azure using Managed Identity..."
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    }
    else {
        Write-Output "Connecting to Azure using Interactive login..."
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception)"
    throw $_.Exception
}

# Main logic
Write-Output "Retrieving Storage Accounts..."
$storageAccounts = Get-TargetStorageAccounts

# Summary counters
$totalStorageAccounts = 0
$totalContainers = 0
$totalProtected = 0
$totalUnprotected = 0

if ($storageAccounts -and $storageAccounts.Count -gt 0) {
    Write-Output " - Found $($storageAccounts.Count) Storage Accounts."
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
            $isProtected = Test-BlobContainerBackup -StorageAccountId $account.Id -ContainerName $container.Name
            if ($isProtected) {
                $protectedCount++
                Write-Output "  [PROTECTED]     Container: $($container.Name)"
            }
            else {
                $unprotectedCount++
                Write-Output "  [NOT PROTECTED] Container: $($container.Name)"
            }
        }
        $totalContainers += $containerCount
        $totalProtected += $protectedCount
        $totalUnprotected += $unprotectedCount
        Write-Output "  -- Storage Account Summary: $containerCount containers, $protectedCount protected, $unprotectedCount unprotected."
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
    Write-Output " - No Storage Accounts found."
}
