<#
.SYNOPSIS
    Checks if Blob containers in specified Storage Accounts are protected by Azure Backup.

.PARAMETER Subscriptions
    Array of subscription IDs or names to scan.

.PARAMETER ResourceGroups
    Array of resource group names to scan.

.PARAMETER StorageAccounts
    Array of storage account names to scan.

.NOTES
    Requires Az.Accounts, Az.Storage, and Az.DataProtection modules.
#>

# Ensure Az modules are imported
Import-Module Az.Accounts -ErrorAction Stop
Import-Module Az.Storage -ErrorAction Stop
Import-Module Az.DataProtection -ErrorAction Stop

# Parameters for Log Ingestion API (optional)
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("AppRegistration", "ManagedIdentity")]
    [string] $logAuthMethod = "AppRegistration",
    [Parameter(Mandatory=$false)]
    [string] $logTenantId,
    [Parameter(Mandatory=$false)]
    [string] $logAppId,
    [Parameter(Mandatory=$false)]
    [string] $logAppSecret,
    [Parameter(Mandatory=$false)]
    [string] $logDCEUri,
    [Parameter(Mandatory=$false)]
    [string] $logDCRImmutableId,
    [Parameter(Mandatory=$false)]
    [string] $logDCRStreamName
)

function Get-LogIngestionApiAuthToken {
    if ($logAuthMethod -eq "AppRegistration") {

        if (-not $logTenantId -or -not $logAppId -or -not $logAppSecret) {
            throw "For AppRegistration authentication, logTenantId, logAppId, and logAppSecret must be provided."
        }

        $scope= [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")
        $body = "client_id=$($logAppId)&scope=$scope&client_secret=$($LogAppSecret)&grant_type=client_credentials";
        $headers = @{"Content-Type"="application/x-www-form-urlencoded"};
        $uri = "https://login.microsoftonline.com/$($logTenantId)/oauth2/v2.0/token"

        $bearerToken = (Invoke-RestMethod `
            -Uri $uri `
            -Method "Post" `
            -Headers $headers `
            -Body $body).access_token

        return $bearerToken
    }
    else {
        throw "Invalid logAuthMethod specified. Use 'AppRegistration'."
    }
}

# Helper: Get all Backup Vaults in the current subscription, with ResourceGroupName
function Get-AllBackupVaults {
    $vaults = Get-AzDataProtectionBackupVault -ErrorAction SilentlyContinue
    foreach ($vault in $vaults) {
        $azRes = Get-AzResource -ResourceId $vault.Id -ErrorAction SilentlyContinue
        if ($azRes) {
            $vault | Add-Member -NotePropertyName SubscriptionId -NotePropertyValue $azRes.SubscriptionId -Force
            $vault | Add-Member -NotePropertyName ResourceGroupName -NotePropertyValue $azRes.ResourceGroupName -Force
        }
    }
    return $vaults
}

# Helper: Get all storage accounts in scope
function Get-TargetStorageAccounts {
    $allAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
    return $allAccounts | Sort-Object -Property Id -Unique
}

# Helper: Check if a blob container is protected by Azure Backup in any Backup Vault
function Test-BlobContainerBackup {
    param(
        [string] $StorageAccountId,
        [string] $ContainerName
    )
    $vaults = Get-AllBackupVaults
    foreach ($vault in $vaults) {
        $backupInstances = Get-AzDataProtectionBackupInstance `
            -ResourceGroupName $vault.ResourceGroupName `
            -VaultName $vault.Name `
            -ErrorAction SilentlyContinue
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

# Helper: Send logs to Log Analytics via Log Ingestion API
function Send-LogIngestionApiLog {
    param(
        [Parameter(Mandatory=$true)]
        [array] $LogEntries
    )

    $accessToken = Get-LogIngestionApiAuthToken
    if (-not $accessToken) {
        throw "Failed to obtain access token for Log Ingestion API."
    }

    $uri = "$($logDCEUri)/dataCollectionRules/$($logDCRImmutableId)/streams/$($logDCRStreamName)?api-version==2023-01-01"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }
    $body = ${ "stream" = $StreamName; "records" = $LogEntries } | ConvertTo-Json -Depth 10

    Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ErrorAction Stop
}

# Main logic
$storageAccounts = Get-TargetStorageAccounts
$results = @()
foreach ($account in $storageAccounts) {
    Write-Host "Checking Storage Account: $($account.StorageAccountName) in Resource Group: $($account.ResourceGroupName)"
    $ctx = $account.Context
    $containers = Get-AzStorageContainer -Context $ctx -ErrorAction SilentlyContinue
    foreach ($container in $containers) {
        $isProtected = $false
        $vaultId = $null
        $policyId = $null
        $vaults = Get-AllBackupVaults
        foreach ($vault in $vaults) {
            $backupInstances = Get-AzDataProtectionBackupInstance `
                -ResourceGroupName $vault.ResourceGroupName `
                -VaultName $vault.Name `
                -ErrorAction SilentlyContinue

            if ($backupInstances) {
                foreach ($instance in $backupInstances) {
                    $dsInfo = $instance.Property.DataSourceInfo
                    if ($dsInfo.Type -eq "Microsoft.Storage/storageAccounts/blobServices" -and $dsInfo.ResourceId -eq $account.Id) {
                        $containerList = $instance.Property.PolicyInfo.PolicyParameter.BackupDatasourceParametersList.ContainersList
                        if ($containerList -contains $container.Name) {
                            $isProtected = $true
                            $vaultId = $vault.Id
                            $policyId = $instance.Property.PolicyInfo.PolicyId
                            break
                        }
                    }
                }
            }
        }

        $result = [PSCustomObject]@{
            SubscriptionId = $account.Id.Split('/')[2]
            ResourceGroup = $account.ResourceGroupName
            StorageAccountName = $account.StorageAccountName
            StorageAccountId = $account.Id
            ContainerName = $container.Name
            BackupVaultId = $vaultId
            BackupPolicyId = $policyId
            IsBackedUp = $isProtected
            TimeGenerated = (Get-Date).ToUniversalTime()
        }
        $results += $result

        if ($isProtected) {
            Write-Host "  [PROTECTED]     Container: $($container.Name)"
        } else {
            Write-Host "  [NOT PROTECTED] Container: $($container.Name)"
        }
    }
}

# Send to Log Analytics via Log Ingestion API if parameters provided
if ($logDCRStreamName -and $results.Count -gt 0) {
    Send-LogIngestionApiLog `
        -LogEntries $results
}
