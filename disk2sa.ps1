###############################################################################
### disk2sa.ps1
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
    [string]$DestVHDFileName = "",

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

if ($DestVHDFileName -eq "") {
    $strDestVHDFileName = $ManagedDiskName + ".vhd"
}
else {
    $strDestVHDFileName = $DestVHDFileName
}

$blnUseConnectedAccount = $UseConnectedAccount

if ($blnUseConnectedAccount) {
    # Check for a connection to Azure
    $objAzContext = Get-AzContext

    if ($null -eq $objAzContext) {
        Write-Host "Not connected to Azure. Please run Connect-AzAccount to login."
        exit
    }
    else {
        Write-Host "Connected to Azure using Azure Account: $($objAzContext.Account)"
    }
}
else {
    Write-Host "Script only supports conencting to Azure using an Entra Id account."
    Write-Host "Run Connect-AzAccount to login and then rerun the script with the UseConnectedAccount parameter."
    exit
}

# Set the context to the Subscription Id where Managed Disk is created
Select-AzSubscription -SubscriptionId $strSubscriptionId

# Generate the SAS for the Managed Disk
$objManagedDiskSAS = Grant-AzDiskAccess `
    -ResourceGroupName $strResourceGroupName `
    -DiskName $strManagedDiskName `
    -DurationInSecond $intSASExpiryDuration `
    -Access Read

# Create the context of the Storage Account where the underlying VHD of the Managed Disk will be copied
#   This assumes a user is logged in with the necessary permissions to the Storage Account using the Connect-AzAccount cmdlet.

if ($blnUseConnectedAccount) {
    $objDestStorageAccountContext = New-AzStorageContext `
        -StorageAccountName $strStorageAccountName `
        -UseConnectedAccount
}
else {
    Write-Host "Script only supports conencting to Azure using an Entra Id account."
    Write-Host "Run Connect-AzAccount to login and then rerun the script with the UseConnectedAccount parameter."
    exit
}

Start-AzStorageBlobCopy `
    -AbsoluteUri $objManagedDiskSAS.AccessSAS `
    -DestContainer $strStorageContainerName `
    -DestContext $objDestStorageAccountContext `
    -DestBlob $strDestVHDFileName
