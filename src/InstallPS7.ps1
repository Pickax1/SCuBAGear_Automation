# Define the GitHub API URL for the latest PowerShell release
$apiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"

# Fetch the latest release information
$releaseInfo = Invoke-RestMethod -Uri $apiUrl

# Extract the URL for the MSI file from the release assets
$msiUrl = $releaseInfo.assets | Where-Object { $_.name -like "*win-x64.msi" } | Select-Object -ExpandProperty browser_download_url

# Define the path to save the MSI file
$msiPath = "$env:TEMP\PowerShell-latest-win-x64.msi"

# Download the MSI file
$ProgressPreference = 'SilentlyContinue' # Speed up the download
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

# Install the MSI file silently
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $msiPath, "/quiet", "/norestart" -Wait

# Clean up the MSI file after installation
Remove-Item -Path $msiPath

$VaultName = $ENV:VaultName
$CertName = $ENV:CertName

# Retrieve an Access Token
if($ENV:PrivateEndpoints -eq 'Yes' -and $env:IDENTITY_ENDPOINT -like "http://10.92.0.*:2377/metadata/identity/oauth2/token?api-version=1.0"){
    $identityEndpoint = " http://169.254.128.1:2377/metadata/identity/oauth2/token?api-version=1.0"
}else{
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

$uri = $identityEndpoint + '&resource=' + $RawVaultURL + '&principalId=' + $principalId
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
#$PassName = 'Pass'
#$Password = (Invoke-RestMethod -Uri "$($VaultURL)/Secrets/$($PassName)/?api-version=7.4" -Headers $headers2).Value
#$SS = ConvertTo-SecureString $Password -AsPlainText -Force
$PrivKey = (Invoke-RestMethod -Uri "$($VaultURL)/Secrets/$($CertName)/?api-version=7.4" -Headers $headers2).Value

# Decode the Base64 string
$pfxBytes = [Convert]::FromBase64String($PrivKey)

# Create an X509Certificate2 object from the PFX bytes
$pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
#$pfxCert.Import($pfxBytes, $SS, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
$pfxCert.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

# Import the certificate into the specified certificate store
#$store1 = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
#$store1.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
#$store1.Add($pfxCert)
#$store1.Close()

$store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store2.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store2.Add($pfxCert)
$store2.Close()

$FilePath = 'C:\Program Files\PowerShell\7\pwsh.exe'
if($FilePath){
    Start-Process -FilePath $FilePath -ArgumentList "-file", "C:\Run_SCuBA.ps1" -Wait
}else{
    Start-Sleep 45
    if($FilePath){
        Start-Process -FilePath $FilePath -ArgumentList "-file", "C:\Run_SCuBA.ps1" -Wait
    }else{
        Write-Error "Filepath not found"
    }
}
