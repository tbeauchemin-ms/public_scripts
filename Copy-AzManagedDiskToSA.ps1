###############################################################################
### Copy-AzManagedDiskToSA.ps1
###   Script to copy the VHD of a managed disk to a storage account.
###############################################################################

param(

    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$ManagedDiskName,

    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory=$true)]
    [string]$StorageContainerName,

    [Parameter(Mandatory=$false)]
    [string]$DestVHDBlobName = "",

    [Parameter(Mandatory=$false)]
    [bool]$UseAzCopy = $true,

    [Parameter(Mandatory=$false)]
    [bool]$UseConnectedAccount = $true

)

# Default values

$intSASExpiryDuration = 3600
$objDestStorageAccountContext = $null

# Copy the Parameters to local variables in case additional logic maybe needed.

$strSubscriptionId = $SubscriptionId
$strResourceGroupName = $ResourceGroupName
$strManagedDiskName = $ManagedDiskName

$strStorageAccountName = $StorageAccountName
$strStorageContainerName = $StorageContainerName

if ($DestVHDBlobName -eq "") {
    $strDestVHDBlobName = $ManagedDiskName + ".vhd"
}
else {
    $strDestVHDBlobName = $DestVHDBlobName
}

$blnUseAzCopy = $UseAzCopy
$blnUseConnectedAccount = $UseConnectedAccount

# Check for a connection to Azure

if ($blnUseConnectedAccount) {

    $objAzContext = Get-AzContext

    if ($null -eq $objAzContext) {
        Write-Host "Not connected to Azure. Please run Connect-AzAccount to login."
        exit
    }
    else {
        Write-Host "Connected to Azure using..."
        Write-Host " - Azure Account: $($objAzContext.Account)"
        Write-Host " - Entra Id Tenant: $($objAzContext.Tenant)"
    }
}
else {
    Write-Error "Script only supports conencting to Azure using an Entra Id."
    Write-Error "Run Connect-AzAccount to login and then rerun the script with the UseConnectedAccount parameter."
    exit
}

# Set the context to the Subscription Id where Managed Disk is created

Write-Host "Setting the Subscription to: $($strSubscriptionId)"
Set-AzContext -SubscriptionId $strSubscriptionId

# Generate the SAS for the Managed Disk

Write-Host "Obtaining access to the Managed Disk..."
Write-Host " - Resource Group: $($ResourceGroupName)"
Write-Host " - Managed Disk: $($ManagedDiskName)"

$objManagedDiskSAS = Grant-AzDiskAccess `
    -ResourceGroupName $strResourceGroupName `
    -DiskName $strManagedDiskName `
    -DurationInSecond $intSASExpiryDuration `
    -Access Read

if ($null -eq $objManagedDiskSAS) {
    Write-Error "Failed to obtain access to the Managed Disk $($ManagedDiskName) in Resource Group $($ResourceGroupName) under Subscription $($strSubscriptionId)."
    exit
}

Write-Host "Managed Disk access granted..."
Write-Host " - SAS Token: $($objManagedDiskSAS.AccessSAS)"

# Check if AzCopy is to be used to copy the VHD of the Managed Disk to the Storage Account

if ($blnUseAzCopy) {

    # Use AzCopy to copy the VHD of the Managed Disk to the Storage Account

    $strAzCopyCommand = "azcopy copy '"
    $strAzCopyCommand += $objManagedDiskSAS.AccessSAS + "' "

    if ($blnUseConnectedAccount) {
        $Env:AZCOPY_AUTO_LOGIN_TYPE="PSCRED"
        $strAzCopyCommand += "https://" + $strStorageAccountName + ".blob.core.windows.net/" + $strStorageContainerName + "/" + $strDestVHDBlobName
    }
    else {
        Write-Error "Script only supports conencting to Azure using an Entra Id."
        Write-Error "Run Connect-AzAccount to login and then rerun the script with the UseConnectedAccount parameter."
        exit
    }

    Write-Host "Using AzCopy to copy Managed Disk to the Storage Account..."
    Write-Host " - AzCopy Command: $($strAzCopyCommand)"

    Invoke-Expression $strAzCopyCommand

}
else {

    if ($blnUseConnectedAccount) {
        $objDestStorageAccountContext = New-AzStorageContext `
            -StorageAccountName $strStorageAccountName `
            -UseConnectedAccount
    }
    else {
        Write-Error "Script only supports conencting to Azure using an Entra Id account."
        Write-Error "Run Connect-AzAccount to login and then rerun the script with the UseConnectedAccount parameter."
        exit
    }

    Start-AzStorageBlobCopy `
        -AbsoluteUri $objManagedDiskSAS.AccessSAS `
        -DestContainer $strStorageContainerName `
        -DestContext $objDestStorageAccountContext `
        -DestBlob $strDestVHDBlobName

}
