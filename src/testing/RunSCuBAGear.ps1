# Environment values
$principalId = $ENV:MIPrincipalID
$clientId    = $ENV:ClientID       # App registration ID
$tenantId    = $ENV:TenantID
$Environment = $ENV:TenantLocation

# ARM environment resolution
$AzureEnvironment = switch ($Environment.ToLower()) {
    "commercial" { "AzureCloud" }
    "gcc"        { "AzureCloud" }
    "gcchigh"    { "AzureUSGovernment" }
    "dod"        { "AzureUSGovernment" }
    default      { "AzureCloud" }
}

# Normalize endpoint
$identityEndpoint = if (($ENV:PrivateEndpoints -eq 'Yes' -or $ENV:Vnet -eq 'Yes') -and
    $env:IDENTITY_ENDPOINT -like "http://10.92.0.*:2377/*") {
    "http://169.254.128.1:2377/metadata/identity/oauth2/token?api-version=1.0"
} else {
    $env:IDENTITY_ENDPOINT
}

# Step 1: Get initial token for AzureADTokenExchange
$audience = 'api://AzureADTokenExchange'
$encodedAudience = [uri]::EscapeDataString($audience)

$headers = @{
    secret = $env:IDENTITY_HEADER
    "Content-Type" = "application/x-www-form-urlencoded"
}
$uri = "$identityEndpoint&resource=$encodedAudience&principalId=$principalId"
$exchangeToken = (Invoke-RestMethod -Uri $uri -Headers $headers -Method GET).access_token

# Step 2: Exchange token for ARM access
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$scope = "https://management.azure.com/.default"
$formBody = @{
    client_id = $clientId
    client_assertion = $exchangeToken
    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    scope = $scope
    grant_type = 'client_credentials'
} | ForEach-Object {
    [System.Web.HttpUtility]::UrlEncode($_.Key) + '=' + [System.Web.HttpUtility]::UrlEncode($_.Value)
} -join '&'

$tokenHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
$armToken = (Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Headers $tokenHeaders -Body $formBody).access_token

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

# Step 3: Connect with token
Connect-AzAccount -AccessToken $armToken -AccountId $clientId -TenantId $tenantId

# Create REST headers for Storage
$storageHeaders = @{
    Authorization  = "Bearer $armToken"
    "x-ms-version" = "2022-11-02"
}

# Upload results to blob storage
function Invoke-StorageTransfer {
    try {
        Write-Output "Federated identity successfully connected to Azure."

        $OutPutContainerName = "scuba-$tenantId-$Date".ToLower()
        $Report = (Get-ChildItem -Path "C:\" -Filter "M365Baseline*" | 
                   Sort-Object -Property LastWriteTime -Descending | 
                   Select-Object -First 1).Name

        # Create container (if it doesn't exist)
        $containerUri = "https://$StorageAccountName.blob.core.windows.net/$OutPutContainerName?restype=container"
        Invoke-RestMethod -Uri $containerUri -Method PUT -Headers $storageHeaders -ErrorAction SilentlyContinue
        Write-Output "Blob container ready: $OutPutContainerName"

        if ($null -ne $Report) {
            Get-ChildItem -Path "C:\$Report" -Recurse | ForEach-Object {
                $filePath = $_.FullName
                $relativePath = $_.FullName.Substring(("C:\$Report\").Length)
                $blobUri = "https://$StorageAccountName.blob.core.windows.net/$OutPutContainerName/$relativePath"

                Invoke-RestMethod -Uri $blobUri -Method PUT -Headers @{
                    Authorization = "Bearer $armToken"
                    "x-ms-version" = "2022-11-02"
                    "x-ms-blob-type" = "BlockBlob"
                    "x-ms-date" = (Get-Date).ToUniversalTime().ToString("R")
                } -InFile $filePath -ContentType "application/octet-stream"

                Write-Output "Uploaded: $relativePath"
            }
        } else {
            Write-Error "No report was found to upload."
        }
    } catch {
        Write-Error "Storage upload failed: $_"
    }
}

$containerName = $ENV:ContainerName
$storageAccount = $ENV:StorageAccountName
$blobBaseUri = "https://$storageAccount.blob.core.windows.net/$containerName"
$headers = @{
    Authorization  = "Bearer $armToken"
    "x-ms-version" = "2022-11-02"
}

$uri = "$blobBaseUri?restype=container&comp=list"
$blobList = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers

$StorageItems = $blobList.EnumerationResults.Blobs.Blob
$MostRecentinStorage = $StorageItems | Where-Object { $_.Name -like "ScubaGear-*.zip" } | Sort-Object -Property Last-Modified -Descending | Select-Object -First 1
$ConfiginStorage = $StorageItems | Where-Object { $_.Name -eq "ScubaGearConfig.yaml" }

$ConfigFilePath = "C:\ScubaGearConfig.yaml"
$ConfigUri = "$blobBaseUri/$($ConfiginStorage.Name)"
Invoke-RestMethod -Uri $ConfigUri -Headers $headers -OutFile $ConfigFilePath

(Get-Content $ConfigFilePath) `
    -replace '\${CertificateThumbprint}', $CertificateThumbprint `
    -replace '\${ClientId}', $ClientID `
    -replace '\${Org}', $Org `
    -replace '\${Environment}', $Environment |
    Set-Content $ConfigFilePath

# GitHub info
$githubApiUrl = "https://api.github.com/repos/cisagov/ScubaGear/releases/latest"
$githubResponse = Invoke-RestMethod -Uri $githubApiUrl -Headers @{ "User-Agent" = "PowerShell" }
$latestReleaseUrl = ($githubResponse.assets | Where-Object { $_.name -like "ScubaGear*.zip" }).browser_download_url
$ZipName = $githubResponse.assets.name
$destinationPath = "C:\$ZipName"

$StorageVersion = $MostRecentinStorage.Name.Split('-')[-1] -replace '.zip',''
$GitHubVersion  = $ZipName.Split('-')[-1] -replace '.zip',''

if ($StorageVersion -lt $GitHubVersion) {
    Invoke-WebRequest -Uri $latestReleaseUrl -OutFile $destinationPath

    # Upload latest
    $uploadUri = "$blobBaseUri/$ZipName"
    Invoke-RestMethod -Uri $uploadUri -Method PUT -Headers @{
        Authorization = "Bearer $armToken"
        "x-ms-version" = "2022-11-02"
        "x-ms-blob-type" = "BlockBlob"
        "x-ms-date" = (Get-Date).ToUniversalTime().ToString("R")
    } -InFile $destinationPath -ContentType "application/zip"

    # Remove old version if present
    if ($null -ne $MostRecentinStorage) {
        $deleteUri = "$blobBaseUri/$($MostRecentinStorage.Name)"
        Invoke-RestMethod -Uri $deleteUri -Method DELETE -Headers $headers
    }

    Expand-Archive -Path $destinationPath -DestinationPath "C:\" -Force
    $StartPath = $ZipName.Replace('.zip','')
    Write-Output "Updated ScubaGear module uploaded and extracted."

} else {
    Write-Output "The file in Azure Storage is already up-to-date."
    $localPath = "C:\$($MostRecentinStorage.Name)"
    Invoke-RestMethod -Uri "$blobBaseUri/$($MostRecentinStorage.Name)" -Headers $headers -OutFile $localPath
    Expand-Archive -Path $localPath -DestinationPath "C:\" -Force
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
