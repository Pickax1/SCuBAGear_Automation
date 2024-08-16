<#
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

## Requires Az.Accounts,

####################################################
# Step 1 - Making connections and setting variables
####################################################
Write-Host "Step 1: Connecting to Azure and setting variables" -ForegroundColor Yellow
# Connect
Connect-AzAccount

# Retrieve all resource groups
Get-AzResourceGroup | Select-Object ResourceGroupName, Location | Out-Host

$RG = Read-Host "   Enter your Resource Group Name that you deployed the ARM template to, if unknown review the list from above:"

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
if(Get-Module -ListAvailable Az.Storage){
    Import-Module Az.Storage
    $SA = (Get-AzStorageAccount -ResourceGroupName $RG).StorageAccountName
}Else{
    Install-Module Az.Storage -Confirm:$False
    Import-Module Az.Storage
    $SA = (Get-AzStorageAccount -ResourceGroupName $RG).StorageAccountName
}

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

# Non-Interactive Permission Requirements - https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md
$roles = @(
    "Directory.Read.All", #Entra ID and SharePoint
    "GroupMember.Read.All", #Entra ID
    "Organization.Read.All", #Entra ID
    "Policy.Read.All", #Entra ID
    "RoleManagement.Read.Directory", #Entra ID
    "User.Read.All", #Entra ID
    "PrivilegedEligibilitySchedule.Read.AzureADGroup", #Entra ID
    "PrivilegedAccess.Read.AzureADGroup", #Entra ID
    "RoleManagementPolicy.Read.AzureADGroup", #Entra ID
    "Sites.FullControl.All", # SharePoint
    "Exchange.ManageAsApp" # Defender and Exchange
)

# Assign API permissions to Service Principal
Write-Output "  Connecting to Microsoft Graph to assign $($Roles.count) API permissions to $($SP.DisplayName) Service Principal"
Connect-MgGraph -Scopes Application.Read.All, AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory
$getGPerms = (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").approles | Where-Object{$_.Value -in $Roles}
$GraphID = (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").id

# Assign roles for Graph
foreach ($perm in $getGPerms){
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID -PrincipalId $ServicePrincipalID -ResourceId $GraphID -AppRoleId $perm.id
}

# Add Service Principal to the appropriate groups
# https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#service-principal
# Define roles
$roles = @("Global Reader")

# Assign roles
foreach ($role in $roles) {
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$role'"
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $servicePrincipalId -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
}

$Scope = (Get-AzStorageAccount -ResourceGroupName $RG -Name $SA).id
$AZRoles = "Storage Account Contributor", "Storage Blob Data Contributor"

foreach ($AZRole in $AZRoles){
    New-AzRoleAssignment -ApplicationId $sp.AppId -RoleDefinitionName $AZRole -Scope $Scope
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

$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AutoAccountName`?api-version=2021-06-22&`$expand=properties(`$select=automationHybridServiceUrl)"
$HybridURL = ((Invoke-AzRestMethod -Uri $uri).Content | ConvertFrom-Json).properties.automationHybridServiceUrl
 
# Construct the Registration URL
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
        Write-Output "  Hybrid Worker Extension was successfully installed on $($VMName)" -ForegroundColor Green
    }else{
        Write-Host "   Hybrid Worker Extension failed to install" -ForegroundColor Red
    }
}Catch{
    Write-Error $_.Exception
}

Write-Output "  Restarting Hybrid Worker Service on $($SCuBAVM.Name) Virtual Machine to jump start hybrid worker connection"
# Add code to restart the service
$Script = @"
    Restart-Service -Name HybridWorkerService -Force
"@
Invoke-AzVMRunCommand -ResourceGroupName $VMResourceGroup -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $Script

###########################################################
# Step 5 - Associate Service Principal with Power Platform
###########################################################
<#
    Write-Host "Step 5: Performing Power Platform Requirements" -ForegroundColor Yellow
    # https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#power-platform
    Import-Module Microsoft.PowerApps.Administration.PowerShell
    $appId = ($SP).AppID
    $TenantID = ($SP).AppOwnerOrganizationID

    # Login interactively with a tenant administrator for Power Platform
    $PowerLogon = Add-PowerAppsAccount -Endpoint prod -TenantID $tenantId 

    # Register a new application, this gives the SPN / client application same permissions as a tenant admin
    $PowerAppSetup = New-PowerAppManagementApp -ApplicationId $appId
#>

##########
# Cleanup
##########
Disconnect-AzAccount
Disconnect-MgGraph
