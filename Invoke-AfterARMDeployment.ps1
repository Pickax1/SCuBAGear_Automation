<#
    .SYNOPSIS  
    This script is used to automate the deployment of SCuBAGear on a Virtual Machine (VM) in Azure.

    .DESCRIPTION
    This script will automate the deployment of SCuBAGear on a Virtual Machine (VM) in Azure. The script will create a self-signed certificate on the VM, create a service principal, assign the service principal with the correct permissions in order to run SCuBAGear, add the hybrid worker extension on the VM, and associate the service principal with Power Platform.

    .PARAMETER Environment
    The environment to deploy SCuBAGear to, the default is commercial. The options are commercial, gcc, gcchigh, and dod.

    .EXAMPLE
    Invoke-AfterARMDeployment.ps1 -Environment commercial

    .NOTES
    File Name      : Invoke-AfterARMDeployment.ps1
    This script will need to be ran after deploying the ARM template located at the below GitHUb repo
      - https://github.com/Pickax1/SCuBAGear_Automation/tree/main

    Steps
    1. Connect to Azure and setup variables
    2. Create Self-Signed certificate on SCuBA Virtual Machine (VM)
      - Save the thumbprint, start/end date to variables in the runbook for use authenticating with Microsoft Graph
    3. Create a service principal and associate the certificate and assign the service principal with the correct permissions in order to run SCuBAGear
      - Write values to the runbook variables for use with Microsoft Graph
    4. Add the hybrid worker extension on the VM and to the hybrid worker group
    5. Power Platform requirements

#>

Param(
    #Azure government or commercial
    [Parameter(Mandatory=$true)]
    [ValidateSet("commercial","gcc","gcchigh","dod")]
    [string]$Environment = "commercial"
)

# Check and install required modules if they are not already installed
$modules = @("Az.Accounts", "Az.Automation", "Az.Compute", "Az.Resources", "Az.Storage", "Microsoft.Graph.Authentication", "Microsoft.Graph.Applications", "Microsoft.Graph.Identity.Governance", "Microsoft.PowerApps.Administration.PowerShell")

foreach ($module in $modules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Try{
            Write-Host "Installing Module: $module"
            Install-Module -Name $module -Confirm:$False
        }Catch{
            Write-Error "Encountered error installing module: $module"
        }   
    }
    Try{
        Write-Host "Importing Module: $module"
        Import-Module -Name $module
    }Catch{
        Write-Error "Encountered error importing module: $module"
    }   
}

####################################################
# Step 1 - Making connections and setting variables
####################################################
switch ($Environment) {
    "commercial" {
        $AzureEnvironment = "AzureCloud"
        $ManagementURL = "https://management.azure.com"
        $GraphEnvironment = "Global"
    }
    "gcc" {
        $AzureEnvironment = "AzureCloud"
        $ManagementURL = "https://management.azure.com"
        $GraphEnvironment = "Global"
    }
    "gcchigh" {
        $AzureEnvironment = "AzureUSGovernment"
        $ManagementURL = "https://management.usgovcloudapi.net"
        $GraphEnvironment = "USGov"

    }
    "dod" {
        $AzureEnvironment = "AzureUSGovernment"
        $ManagementURL = "https://management.usgovcloudapi.net"
        $GraphEnvironment = "USGovDoD"
    }
}
Write-Host "Step 1: Connecting to Azure and setting variables" -ForegroundColor Yellow
# Connect
Connect-AzAccount -Environment $AzureEnvironment

# Retrieve all resource groups
$RGs = Get-AzResourceGroup | Select-Object ResourceGroupName, Location 
$RGs | Out-Host

$RG = Read-Host "   Enter your Resource Group Name that you deployed the ARM template to, if unknown review the list from above:"

if ($RGs.ResourceGroupName -contains $RG) {
    # Selected valid RG
} else {
    Write-Error "Invalid input. Please enter a valid Resource Group"
    $RG = Read-Host "   Enter your Resource Group Name that you deployed the ARM template to, if unknown review the list from above:"
}

Write-Output "  Creating Variables for later use"
$VMTag = (Get-AzResource -Tag @{ "Project"="SCuBAGear_Automation"} -ResourceType 'Microsoft.Compute/VirtualMachines').Name
$SCuBAVM = Get-AzVM -Name $VMTag -ResourceGroupName $RG
$VMResourceGroup = $SCuBAVM.Id.Split('/')[4]
$VmId = $SCuBAVM.Id
$VM_ID = $SCuBAVM.VmId
$VMName = $SCuBAVM.Name
$AutoAccountName = (Get-AzAutomationAccount -ResourceGroupName $RG).AutomationAccountName
$SubscriptionID = (Get-AzSubscription).ID
$Org = (Get-AzTenant).DefaultDomain
$SA = (Get-AzStorageAccount -ResourceGroupName $RG).StorageAccountName

########################################
# Step 2 - Create the certificate on VM
########################################
Write-Host "Step 2: Creating certificate on $($VMName) Virtual Machine, this will take around 1-2 minutes to complete `r`n" -ForegroundColor Yellow
# Script to create Self-Signed Certificate
$Script = @"
Try{
    `$SCuBACertParams = @{
        CertStoreLocation = "cert:\LocalMachine\My" # Needed since runbook runs as SYSTEM
        Subject = "CN=SCuBAAutomationCert"
        NotAfter = (Get-Date).AddYears(1) # Cert will expire 1 year after issued
    }
    `$cert = New-SelfSignedCertificate @SCuBACertParams

    `$base64Cert = [System.Convert]::ToBase64String(`$cert.GetRawCertData())

    `$KeyValueArray = [System.Collections.ArrayList]@()
    `$KeyValueArray.Add(`$base64Cert)

    Write-Output "Thumbprint: `$(`$cert.Thumbprint)"
    Write-Output "StartDate: `$(`$cert.NotBefore)"
    Write-Output "EndDate: `$(`$cert.NotAfter)"
    Write-Output "KeyValue: `$KeyValueArray"
}Catch{
    Write-Error -Message `$_.Exception    
}
"@

$result = Invoke-AzVMRunCommand -ResourceGroupName $VMResourceGroup -Name $VMName -CommandId "RunPowerShellScript" -ScriptString $script

# Extract the output from the result variable, this will be used when creating the Service Principal
$outputstrings = $result.Value[0].Message -split "`n"

# Create a hashtable to store the parsed values
$outputHashTable = @{}
foreach ($line in $outputstrings) {
    if ($line -match "(?m)^\s*(\w+):\s*(.+)$") {
        $key = $matches[1].Trim()
        $value = $matches[2].Trim()
        $outputHashTable[$key] = $value
    }
}

# Use the captured information
$Thumbprint = $outputHashTable['Thumbprint']
$KeyValue = $outputHashTable['KeyValue']
$StartDate = $outputHashTable['StartDate']
$EndDate = $outputHashTable['EndDate']

########################################
# Step 3 - Create the Service Principal
########################################
Write-Host "Step 3: Creating Service Principal: SCuBAGearAutomation and loading certificate thumbprint from $($VMName)  `r`n" -ForegroundColor Yellow
$SP = New-AzADServicePrincipal -DisplayName SCuBAGearAutomation -CertValue $keyValue -EndDate $EndDate -StartDate $StartDate
$ServicePrincipalID = $SP.ID

# Update Variables used to connect to Microsoft Graph when running SCuBAGear
Write-Output "  Updating Variables on $($AutoAccountName) Automation Account, these are used to connect to Microsoft Graph when running SCuBAGear on $($VMName) VM"
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'ClientID' -Value ($SP).AppID -Encrypted $True | Out-Null
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'TenantID' -Value ($SP).AppOwnerOrganizationID -Encrypted $True | Out-Null
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'CertThumbprint' -Value $Thumbprint -Encrypted $True | Out-Null
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'StorageAccountName' -Value $SA -Encrypted $True | Out-Null
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'Org' -Value $Org -Encrypted $True | Out-Null
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'Environment' -Value $Environment -Encrypted $True | Out-Null

# Download and parse the permissions file
$PermissionsUrl = "https://raw.githubusercontent.com/Pickax1/SCuBAGear_Automation/main/src/SP_Permissions.json"
$permissionsContent = (Invoke-WebRequest -Uri $PermissionsUrl -UseBasicParsing | ConvertFrom-Json)

Connect-MgGraph -Scopes Application.Read.All, AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory -Environment $GraphEnvironment

# Parse the permissions file
foreach ($Product in $($permissionsContent).SCuBAGearPermissions) {
    $ProductName = $Product.ProductName

    $Count = $Product.Permission.count
    For($i = 0; $i -lt $Count; $i++){
        $AppRoleID = $Product.Permission[$i].id
        $Filter = "AppId eq '" + $($Product.resourceAPIAppId) + "'"
        $ProductResourceID = (Get-MgServicePrincipal -Filter $Filter).ID
        $APIPermissionName = $Product.Permission[$i].Name
        Write-Output "  Assigning $($SP.DisplayName) Service Principal $ProductName API Permission: $APIPermissionName"
        $GrpahAPIAssign = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID -PrincipalId $ServicePrincipalID -ResourceId $ProductresourceId -AppRoleId $AppRoleID
    }
}

ForEach($Role in $($PermissionsContent).SCuBAGearRoles){
    $RoleName = $Role.RoleName
    Write-Output "  Assigning $($SP.DisplayName) Service Principal to $RoleName role"
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"
    $RoleAssign = New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $servicePrincipalId -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
}


$Scope = (Get-AzStorageAccount -ResourceGroupName $RG -Name $SA).id
$AZRoles = "Storage Account Contributor", "Storage Blob Data Contributor"

foreach ($AZRole in $AZRoles){
    Write-Output "  Assigning $($SP.DisplayName) Service Principal to $AzRole role"
    $StorageRole = New-AzRoleAssignment -ApplicationId $sp.AppId -RoleDefinitionName $AZRole -Scope $Scope
}

################################################
# Step 4 - Add the VM to the Hybrid Worker Group
################################################
Write-Host "Step 4: Adding Hybrid Worker Extension on $($VMName) Virtual Machine  `r`n" -ForegroundColor Yellow

# Add SCuBA to the Hybrid Worker Group
$HybridGroupName = (Get-AzAutomationHybridWorkerGroup -ResourceGroupName $RG -AutomationAccountName $AutoAccountName).Name
Write-Output "  Adding $($VMName) Virtual Machine to be a member of the $($HybridGroupName)"

$HybridWorkerParams = @{
    Name = $VM_ID
    AutomationAccountName = $AutoAccountName
    HybridRunbookWorkerGroupName = $HybridGroupName
    VmResourceId = $VmId
    ResourceGroupName = $VMResourceGroup
}
New-AzAutomationHybridRunbookWorker @HybridWorkerParams

# Install hybrid worker extension on VM
$VMLocation = $SCuBAVM.Location

# Construct the Registration URL
$uri = "$ManagementURL/subscriptions/$subscriptionId/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AutoAccountName`?api-version=2021-06-22&`$expand=properties(`$select=automationHybridServiceUrl)"
$HybridURL = ((Invoke-AzRestMethod -Uri $uri).Content | ConvertFrom-Json).properties.automationHybridServiceUrl
 
$Settings = @{
    AutomationAccountURL = $HybridURL
}

# Install the Hybrid Worker extension
Try{
    Write-Output "  Installing Hybrid Worker Extension on $($VmName) VM, this will take 2-3 minutes"
    $VMExtension = Set-AzVMExtension -ResourceGroupName $RG -VMName $vmName -Location $VMlocation `
        -Name "HybridWorkerExtension" -Publisher "Microsoft.Azure.Automation.HybridWorker" `
        -ExtensionType "HybridWorkerForWindows" -TypeHandlerVersion "1.1" -Settings $Settings `
        -EnableAutomaticUpgrade $true

    if ((Get-AzVMExtension -ResourceGroupName $RG -VMName $VMName -Name HybridWorkerExtension).ProvisioningState -eq 'Succeeded' ){
        Write-Host "  Hybrid Worker Extension was successfully installed on $($VMName)" -ForegroundColor Green
    }else{
        Write-Host "   Hybrid Worker Extension failed to install" -ForegroundColor Red
    }
}Catch{
    Write-Error $_.Exception
}

###########################################################
# Step 5 - Associate Service Principal with Power Platform
###########################################################

Write-Host "Step 5: Performing Power Platform Requirements" -ForegroundColor Yellow
# https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#power-platform

$appId = ($SP).AppID
$TenantID = ($SP).AppOwnerOrganizationID

# Login interactively with a tenant administrator for Power Platform
$PowerLogon = Add-PowerAppsAccount -Endpoint prod -TenantID $tenantId 

# Register a new application, this gives the SPN / client application same permissions as a tenant admin
$PowerAppSetup = New-PowerAppManagementApp -ApplicationId $appId


################################
# Step 6 - Install PowerShell 7
################################
# Installing PowerShell 7 resolves an error when connecting to Exchange online

Write-Host "Step 6: Installing PowerShell 7 on $($VMName) Virtual Machine  `r`n" -ForegroundColor Yellow
$PwshInstallScript = @"
    # Define the GitHub API URL for the latest PowerShell release
    `$apiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"

    # Fetch the latest release information
    `$releaseInfo = Invoke-RestMethod -Uri `$apiUrl

    # Extract the URL for the MSI file from the release assets
    `$msiUrl = `$releaseInfo.assets | Where-Object { `$_.name -like "*win-x64.msi" } | Select-Object -ExpandProperty browser_download_url

    # Define the path to save the MSI file
    `$msiPath = "`$env:TEMP\PowerShell-latest-win-x64.msi"

    # Download the MSI file
    Invoke-WebRequest -Uri `$msiUrl -OutFile `$msiPath

    # Install the MSI file silently
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", `$msiPath, "/quiet", "/norestart" -Wait

    # Clean up the MSI file after installation
    Remove-Item -Path `$msiPath

    # This is needed so the Hybrid Worker can read the PS 7 ENV Variables, if not the runbook will fail since it's not aware pwsh.exe in valid.
    Restart-Service -Name HybridWorkerService -Force
"@
Invoke-AzVMRunCommand -ResourceGroupName $VMResourceGroup -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $PwshInstallScript

##########
# Cleanup
##########
Disconnect-AzAccount
Disconnect-MgGraph
