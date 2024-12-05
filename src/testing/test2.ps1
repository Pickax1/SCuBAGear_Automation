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
$CertName = 'CN=' + $ENV:CertName
$CertificateThumbprint = (Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -eq $CertName }).Thumbprint
$Date= Get-Date -Format FileDateTime
$Environment = $ENV:TenantLocation
$TenantID = $ENV:TenantID
$ClientID = $ENV:ClientID
$Org = $ENV:Org
$StorageAccountName = $ENV:StorageAccountName

switch ($Environment.ToLower().Trim()) {
    "commercial" {
        $AzureEnvironment = "AzureCloud"
    }
    "gcc" {
        $AzureEnvironment = "AzureCloud"
    }
    "gcchigh" {
        $AzureEnvironment = "AzureUSGovernment"
    }
    "dod" {
        $AzureEnvironment = "AzureUSGovernment"
    }
}

Function Start-ResourceConnection {
    # Connect to Azure and Graph using the service principal and certficate thumbprint
    Write-Output "Connecting to Azure"
    Connect-Azaccount -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID -Environment $AzureEnvironment
}

Start-ResourceConnection
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount

function Invoke-StorageTransfer {
    Try{
        Write-Output "Service Principal Connected to Azure for writing result to Storage Account"
        $OutPutContainerName = "scuba-$TenantID-$Date".ToLower()
        $Report = (Get-ChildItem -Path "C:\" -Filter "M365Baseline*" | Sort-Object -Descending -Property LastWriteTime | select-object -First 1).Name
        
        Try{
            $StorageContainer = New-AzStorageContainer -Name $OutPutContainerName -Context $ctx
            Write-Output "New Azure Blob Container Created for SCuBAGear Results - $OutPutContainerName"
        }Catch{
            Write-Output"Azure Blob Container Exists"
        }
        
        Try{
            if($Report -ne $Null){
                $Items = Get-ChildItem -Path "C:\$Report" -Recurse | Set-AzStorageBlobContent -Container $OutPutContainerName -Context $ctx -WarningAction SilentlyContinue
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
    }
    Invoke-ScuBA @SCuBAParams

    Write-Output "Transferring SCuBAGear results to storage"
    Invoke-StorageTransfer

}

# Download SCuBAGear Module from Storage Account
$containerName = $ENV:ContainerName

# Get the latest release information from GitHub
$githubApiUrl = "https://api.github.com/repos/cisagov/ScubaGear/releases/latest"
$githubResponse = Invoke-RestMethod -Uri $githubApiUrl
$latestReleaseUrl = ($githubResponse.assets | Where-Object { $_.name -like "ScubaGear*.zip" }).browser_download_url
$ZipName = $githubResponse.Assets.name
#$GitHubDate = $githubResponse.created_at
$destinationPath = "C:\$ZipName"

# Get the current version stored in Azure Storage
$MostRecentinStorage = (Get-AzStorageBlob -Container $containerName -Context $ctx | Where-Object {$_.Name -like "ScuBAGear-*.zip"}  | Sort-Object -Descending LastModified)
#$StorageDate = $MostRecentinStorage.LastModified.UtcDateTime

# Compare the versions and update the blob if necessary
$StorageModuleVersion = $MostRecentinStorage.Name.Split('-')[-1] -replace '.zip',''
$GitHubModuleVersion  = $ZipName.Split('-')[-1] -replace '.zip',''
if ($StorageModuleVersion -eq $GitHubModuleVersion) {
    # Download the latest release from GitHub
    $LocalPath = "C:\$ZipName"
    Invoke-WebRequest -Uri $latestReleaseUrl -OutFile $LocalPath

    # Add latest SCuBAGear module to Azure Storage
    Set-AzStorageBlobContent -File $localPath -Container $containerName -Blob $ZipName -Context $ctx -Force -Confirm:$false

    # Remove older version of the SCuBAGear module from Azure Storage
    Remove-AzStorageBlob -Container $containerName -Blob $MostRecentinStorage.Name -Context $ctx -Force -Confirm:$False

    Write-Output "The file in Azure Storage has been updated with the latest version from GitHub."

    # Extract the ZIP file
    Expand-Archive -Path $destinationPath -DestinationPath "C:\" -Force

    $StartPath = $ZipName.Replace('.zip','')

} else {
    Write-Output "The file in Azure Storage is already up-to-date."
    $LocalPath = "C:\$($MostRecentinStorage.Name)"
    Get-AzStorageBlobContent -Container $containerName -Blob $MostRecentinStorage.Name -Destination $LocalPath -Context $ctx

    # Extract the ZIP file
    Expand-Archive -Path $LocalPath -DestinationPath "C:\" -Force
}

Write-Output "Importing SCuBAGear Module...."
$StartPath = $MostRecentinStorage.Name.Replace('.zip','')
$modulePath = "C:\$StartPath\PowerShell\ScubaGear\ScubaGear.psd1"
Import-Module -Name $modulePath

# This will check for depencies and latest versions
Write-Output "Initializing SCuBAGear (This can take awhile)...."
Initialize-SCuBA -ScubaParentDirectory C:\

Start-SCuBA
