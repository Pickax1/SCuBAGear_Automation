$VaultName = $ENV:VaultName
$CertName = $ENV:CertName

# Retrieve an Access Token
if (($ENV:PrivateEndpoints -eq 'Yes' -or $ENV:Vnet -eq 'Yes') -and $env:IDENTITY_ENDPOINT -like "http://10.92.0.*:2377/metadata/identity/oauth2/token?api-version=1.0") {
    $identityEndpoint = "http://169.254.128.1:2377/metadata/identity/oauth2/token?api-version=1.0"
} else {
    $identityEndpoint = $env:IDENTITY_ENDPOINT
}
$identityHeader = $env:IDENTITY_HEADER
$principalId = $ENV:MIPrincipalID
$Environment = $ENV:TenantLocation

switch ($Environment) {
    {"commercial" -or "gcc"} {
        $VaultURL = "https://$($VaultName).vault.azure.net"
        $RawVaultURL = "https%3A%2F%2F" + "vault.azure.net"
    }
    "gcchigh" {
        $VaultURL = "https://$($VaultName).vault.usgovcloudapi.net"
        $RawVaultURL = "https%3A%2F%2F" + "vault.usgovcloudapi.net"
    }
    "dod" {
        $VaultURL = "https://$($VaultName).vault.microsoft.scloud"
        $RawVaultURL = "https%3A%2F%2F" + "vault.microsoft.scloud"
    }
}

$resource = 'https%3A%2F%2Fmanagement.azure.com%2F'  # URL-encoded version of https://management.azure.com/
#$uri = $identityEndpoint + '&resource=' + $RawVaultURL + '&principalId=' + $principalId
$uri = $identityEndpoint + '&resource=' + $resource + '&principalId=' + $principalId

$headers = @{
    secret = $identityHeader
    "Content-Type" = "application/x-www-form-urlencoded"
}
$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

# Access values from Key Vault with token
$accessToken = $Response.access_token
$headers2 = @{
    Authorization = "Bearer $accessToken"
}

$PrivKey = (Invoke-RestMethod -Uri "$($VaultURL)/Secrets/$($CertName)/?api-version=7.4" -Headers $headers2).Value

# Decode the Base64 string
$pfxBytes = [Convert]::FromBase64String($PrivKey)

# Create an X509Certificate2 object from the PFX bytes
$pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfxCert.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

$store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store2.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store2.Add($pfxCert)
$store2.Close()

if((Get-PackageProvider -Name 'NuGet' -ListAvailable -Erroraction SilentlyContinue)){
    # NuGet is installed
    Write-Output "NuGet provider is installed...."
}Else{
    # NuGet wasn't installed, installing now
    Write-Output "Installing NuGet provider...."
    $nuget = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
}

Try{
    if((Get-Module -ListAvailable az.accounts,az.storage -Erroraction SilentlyContinue).Count -eq '2')
    {
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        $moduleImport = Import-Module -Name az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }else{
        # Install and import ScubaGear module if not already installed and loaded
        Write-Output "Installing Az.Accounts and Az.Storage Modules...."
        $moduleImport = Install-Module az.accounts,az.storage -Force -Confirm:$False -WarningAction SilentlyContinue
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        $moduleImport = Import-Module az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }
}Catch{
    Write-Error -Message $_.Exception
}

# Define some variables for Graph connection and writing to the storage account
$CertName = 'CN=' + $ENV:CertName
$CertificateThumbprint = (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -eq $CertName }).Thumbprint
$Date = Get-Date -Format FileDateTime
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
    # Connect to Azure and Graph using the service principal and certificate thumbprint
    Write-Output "Connecting to Azure"
    $azConnect = Connect-AzAccount -AccessToken $access_token -AccountId $principalId -TenantId $ENV:TenantID
    #-ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID -Environment $AzureEnvironment
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
            Write-Output "New Azure Blob Container Created for ScubaGear Results - $OutPutContainerName"
        }Catch{
            Write-Output"Azure Blob Container Exists"
        }

        Try{
            if($Null -ne $Report){
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

# Download ScubaGear Module from Storage Account
$containerName = $ENV:ContainerName

# Get the latest release information from GitHub
$githubApiUrl = "https://api.github.com/repos/cisagov/ScubaGear/releases/latest"
$githubResponse = Invoke-RestMethod -Uri $githubApiUrl
$latestReleaseUrl = ($githubResponse.assets | Where-Object { $_.name -like "ScubaGear*.zip" }).browser_download_url
$ZipName = $githubResponse.Assets.name
#$GitHubDate = $githubResponse.created_at
$destinationPath = "C:\$ZipName"

# Get the current version stored in Azure Storage
$StorageItems = Get-AzStorageBlob -Container $containerName -Context $ctx
$MostRecentinStorage = ($StorageItems | Where-Object {$_.Name -like "ScubaGear-*.zip"}  | Sort-Object -Descending LastModified)
$ConfiginStorage = $StorageItems | Where-Object {$_.Name -eq "ScubaGearConfig.yaml"}

# Save configuration file to local disk
$ConfigFilePath = "C:\ScubaGearConfig.yaml"
$GetConfig = Get-AzStorageBlobContent -Container $containerName -Blob $ConfiginStorage.Name -Destination $ConfigFilePath -Context $ctx

# Replace ScubaGear config file with variables from container
$ConfigFileContents = Get-Content $ConfigFilePath
$ConfigFileContents = $ConfigFileContents -replace '\${CertificateThumbprint}', $CertificateThumbprint
$ConfigFileContents = $ConfigFileContents -replace '\${ClientId}', $ClientID
$ConfigFileContents = $ConfigFileContents -replace '\${Org}', $Org
$ConfigFileContents = $ConfigFileContents -replace '\${Environment}', $Environment
$ConfigFileContents | Set-Content $ConfigFilePath

# Compare the versions and update the blob if necessary
$StorageModuleVersion = $MostRecentinStorage.Name.Split('-')[-1] -replace '.zip',''
$GitHubModuleVersion  = $ZipName.Split('-')[-1] -replace '.zip',''
if ($StorageModuleVersion -lt $GitHubModuleVersion) {
    # Download the latest release from GitHub
    Invoke-WebRequest -Uri $latestReleaseUrl -OutFile $destinationPath

    # Add latest ScubaGear module to Azure Storage
    Set-AzStorageBlobContent -File $destinationPath -Container $containerName -Blob $ZipName -Context $ctx -Force -Confirm:$false

    if($null -eq $StorageModuleVersion){
        Write-Output "No previous version of ScubaGear found in Azure Storage."
    }else{
        # Remove older version of the ScubaGear module from Azure Storage
        Write-Output "Removing older version of ScubaGear from Azure Storage."
        $removeOld = Remove-AzStorageBlob -Container $containerName -Blob $MostRecentinStorage.Name -Context $ctx -Force -Confirm:$False
    }

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

    $StartPath = $MostRecentinStorage.Name.Replace('.zip','')
}

Write-Output "Importing ScubaGear Module...."
$modulePath = "C:\$StartPath\PowerShell\ScubaGear\ScubaGear.psd1"
Import-Module -Name $modulePath

# This will check for depencies and latest versions
Write-Output "Initializing ScubaGear (This can take awhile)...."

# Download OPA since BITS can't be used.
$ProgressPreference = 'SilentlyContinue' # Speed up the download
Invoke-WebRequest -Uri 'https://openpolicyagent.org/downloads/v1.3.0/opa_windows_amd64.exe' -OutFile c:\opa_windows_amd64.exe -UseBasicParsing
mkdir C:\.ScubaGear\Tools
copy-item C:\opa_windows_amd64.exe C:\.ScubaGear\Tools

Initialize-SCuBA -ScubaParentDirectory C:\ -NoOPA

Write-Output "Running ScubaGear Checks...."

if((Test-Path "C:\ScubaGearConfig.yaml" -ErrorAction 0)){
    Write-Output "Configuration file found."
    Invoke-Scuba -ConfigFilePath $ConfigFilePath
}else{
    Write-Output "No Configuration file found."
    $SCuBAParams = @{
        ProductNames = '*'
        OPAPath = 'C:\.ScubaGear\tools\'
        OutPath = 'C:\'
        CertificateThumbprint = $CertificateThumbprint
        AppId = $ClientID
        Organization = $Org
        M365Environment = $Environment
        Quiet = $True
    }
    Invoke-ScuBA @SCuBAParams
}

Write-Output "Transferring ScubaGear results to storage"
Invoke-StorageTransfer
Sleep 3600
