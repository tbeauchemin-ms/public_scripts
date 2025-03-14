# Copy-AzManagedDiskToSA.ps1

The `Copy-ManagedDiskToSA.ps1` script is designed to copy managed disks to a storage account in Azure. This script automates the process of exporting managed disks as VHD files and storing them in a specified storage account.

## Overview

This script is based on the process and script documented in the official Microsoft documentation:
[Copy managed disks to a storage account using PowerShell](https://learn.microsoft.com/en-us/azure/virtual-machines/scripts/virtual-machines-powershell-sample-copy-managed-disks-vhd)

## Usage

To use the script, follow these steps:

1. Ensure you have the necessary Azure PowerShell modules installed.
2. Authenticate to your Azure account using `Connect-AzAccount`.
3. Run the `Copy-AzManagedDiskToSA.ps1` script with the required parameters.

## Parameters

- `-ResourceGroupName`: The name of the resource group containing the managed disk.
- `-DiskName`: The name of the managed disk to be copied.
- `-StorageAccountName`: The name of the storage account where the VHD will be stored.
- `-ContainerName`: The name of the container within the storage account.

## Example

```powershell
Connect-AzAccount

.\Copy-AzManagedDiskToSA.ps1 -ResourceGroupName "myResourceGroup" -DiskName "myManagedDisk" -StorageAccountName "myStorageAccount" -ContainerName "vhds"
```

This example copies the managed disk `myManagedDisk` from the resource group `myResourceGroup` to the storage account `myStorageAccount` in the container `vhds`.

## References

- [Copy managed disks to a storage account using PowerShell](https://learn.microsoft.com/en-us/azure/virtual-machines/scripts/virtual-machines-powershell-sample-copy-managed-disks-vhd)
