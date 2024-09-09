if((Get-PackageProvider -Name 'NuGet' -ListAvailable)){
    # NuGet is installed
    Write-Output "NuGet provider is installed...."
}Else{
    # NuGet wasn't installed, installing now
    Write-Output "Installing NuGet provider...."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
}

Try{
    if((Get-Module -ListAvailable az.accounts,az.storage).Count -eq '2')
    {
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        Import-Module -Name az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }else{
        # Install and import SCuBAGear module if not already installed and loaded
        Write-Output "Installing Az.Accounts and Az.Storage Modules...."
        Install-Module az.accounts,az.storage -Force -Confirm:$False -WarningAction SilentlyContinue
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        Import-Module az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }
}Catch{
    Write-Error -Message $_.Exception
}

# Define some variables for Graph connection and writing to the storage account
$CertificateThumbprint = (Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -eq 'CN=SCuBAGearAutomation' }).Thumbprint
$Date= Get-Date -Format FileDateTime
$Environment = $ENV:TenantLocation
$TenantID = $ENV:TenantID
$ClientID = $ENV:ClientID
$Org = $ENV:Org
$StorageAccountName = $ENV:StorageAccountName
$ContainerName = "scuba-$TenantID-$Date".ToLower()

function Invoke-StorageTransfer {
    Try{
        Write-Output "Service Principal Connected to Azure for writing result to Storage Account"
        $Report = (Get-ChildItem -Path "C:\" -Filter "M365Baseline*" | Sort-Object -Descending -Property LastWriteTime | select-object -First 1).Name
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        
        Try{
            $StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $ctx
            Write-Output "New Azure Blob Container Created for SCuBAGear Results - $ContainerName"
        }Catch{
            Write-Output"Azure Blob Container Exists"
        }
        
        Try{
            if($Report -ne $Null){
                $Items = Get-ChildItem -Path "C:\$Report" -Recurse | Set-AzStorageBlobContent -Container $ContainerName -Context $ctx -WarningAction SilentlyContinue
                Write-Output "The below items have been Uploaded to Azure Blob Storage"

                ForEach($Item in $Items.Name){
                    Write-Output "  - $($Item)"
                }
            }else{
                Write-Error "No report was generated."
            }
        }catch{
            Write-Output "Unable to Upload Report to Blob Storage"
        }
    }Catch{
        Write-Error -Message $_.Exception
        Write-Output "Unable to create blob container"
    }
}
Function Start-SCuBA {

    Write-Output "Running SCuBAGear Checks...."
    $SCuBAParams = @{
        ProductNames = '*'
        OPAPath = 'C:\.scubagear\tools\'
        OutPath = 'C:\'
        CertificateThumbprint = $CertificateThumbprint
        AppId = $ClientID
        Organization = $Org
        M365Environment = $Environment
        Quiet = $True
        MergeJson = $True
    }
    Invoke-ScuBA @SCuBAParams

    Write-Output "Transferring SCuBAGear results to storage"
    Invoke-StorageTransfer

}
Function Start-ResourceConnection {
    # Connect to Azure and Graph using the service principal and certficate thumbprint
    Write-Output "Connecting to Azure"
    Connect-Azaccount -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID
}

Start-ResourceConnection

# Download SCuBAGear Module from Storage Account
$storageAccountName = $ENV:StorageAccountName
$containerName = $ENV:ContainerName

# Get the latest release information from GitHub
$githubApiUrl = "https://api.github.com/repos/cisagov/ScubaGear/releases/latest"
$githubResponse = Invoke-RestMethod -Uri $githubApiUrl
$latestReleaseUrl = ($githubResponse.assets | Where-Object { $_.name -like "ScubaGear*.zip" }).browser_download_url
$ZipName = $githubResponse.Assets.name
$GitHubDate = $githubResponse.created_at
$destinationPath = "C:\$ZipName"

# Get the current version stored in Azure Storage
#$ctx = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName).Context
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
$MostRecentinStorage = (Get-AzStorageBlob -Container $containerName -Context $ctx | Sort-Object -Descending LastModified)
#$blob = Get-AzStorageBlob -Container $containerName -Blob $ZipName -Context $ctx
$StorageDate = $MostRecentinStorage.LastModified.UtcDateTime

# Compare the versions and update the blob if necessary
if ($GitHubDate -gt $StorageDate) {
    # Download the latest release from GitHub
    $LocalPath = "C:\$ZipName"
    Invoke-WebRequest -Uri $latestReleaseUrl -OutFile $LocalPath

    # Overwrite the file in Azure Storage
    Set-AzStorageBlobContent -File $localPath -Container $containerName -Blob $ZipName -Context $ctx

    Write-Output "The file in Azure Storage has been updated with the latest version from GitHub."

    # Extract the ZIP file
    Expand-Archive -Path $destinationPath -DestinationPath "C:\" -Force

} else {
    Write-Output "The file in Azure Storage is already up-to-date."
    $LocalPath = "C:\$($MostRecentinStorage.Name)"
    Get-AzStorageBlobContent -Container $containerName -Blob $MostRecentinStorage.Name -Destination $LocalPath -Context $ctx

    # Extract the ZIP file
    Expand-Archive -Path $LocalPath -DestinationPath "C:\" -Force
}

Write-Output "Importing SCuBAGear Module...."
$StartPath = $ZipName.Replace('.zip','')
$modulePath = "C:\$StartPath\PowerShell\ScubaGear\ScubaGear.psd1"
Import-Module -Name $modulePath

# This will check for depencies and latest versions
Write-Output "Initializing SCuBAGear (This can take awhile)...."
Initialize-SCuBA -ScubaParentDirectory C:\

Start-SCuBA
