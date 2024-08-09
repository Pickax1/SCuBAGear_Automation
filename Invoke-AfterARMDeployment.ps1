<#
    This script will need to be ran after deploying the ARM template located at the below GitHUb repo
      - https://github.com/Pickax1/SCuBAGear_Automation/tree/main

    Steps
    1. Create Self-Signed certificate on SCuBA Virtual Machine (VM)
      - Save the thumbprint, start/end date to variables in the runbook for use authenticating with Microsoft Graph
    2. Create a service principal and associate the certificate and assign the service principal with the correct permissions in order to run SCuBAGear
      - Write values to the runbook variables for use with Microsoft Graph
    3. Add the hybrid worker extension on the VM and to the hybrid worker group

#>

## Requires Az.Accounts,

# Connect
$AZ = Connect-AzAccount

# Retrieve all resource groups
$RGs = Get-AzResourceGroup | Select-Object ResourceGroupName, Location
$RGs

$RG = Read-Host "Enter your Resource Group Name that you deployed the ARM template to, if unknown review the list from above:"

Write-Output "Retrieving information on SCuBA VM"
$SCuBAVM = (Get-AzVM -ResourceGroupName $RG).Name
$VMResourceGroup = $SCuBAVM.Id.Split('/')[4]
$VmId = $SCuBAVM.Id
$VM_ID = $SCuBAVM.VmId
$VMName = $SCuBAVM.Name
$AutoAccountName = (Get-AzAutomationAccount -ResourceGroupName $RG).AutomationAccountName
$SubscriptionID = (Get-AzSubscription).ID

########################################
# Step 1 - Create the certificate on VM
########################################

# Script to create Self-Signed Certificate
$Script = @"
Try{

    `$SCuBACertParams = @{
        CertStoreLocation = "cert:\LocalMachine\My" # Needed since runbook runs as SYSTEM
        Subject = "CN=SCuBAAutomationCert"
        NotAfter = (Get-Date).AddYears(1) # Cert will expire 1 year after issued
    }

    # Create the Self-Signed Certificate and store with the LocalComputer store
    `$cert = New-SelfSignedCertificate @SCuBACertParams
    `$Thumbprint = (`$Cert).Thumbprint
    `$keyValue = [System.Convert]::ToBase64String(`$cert.GetRawCertData())
    `$StartDate = (`$Cert).NotBefore
    `$EndDate = (`$Cert).NotAfter

    # Test
    echo "Thumbprint: `$Thumbprint" >> C:\test.txt
    echo "KeyValue: `$KeyValue" >> C:\test.txt
    echo "StartDate: `$StartDate" >> C:\test.txt
    echo "EndDate: `$EndDate" >> C:\test.txt

    `$FullOutput = GC C:\Test.txt
    return `$FullOutput

    # Cleanup
    sleep 5
    Remove-Item C:\test.txt -Force

}Catch{
    Write-Error -Message `$_.Exception
}
"@
# Run the script on the SCuBA VM
Write-Output "Creating Self-Signed Certificate on: $($VMName)"
$Result = Invoke-AzVMRunCommand -ResourceGroupName $VMResourceGroup -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $Script

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
# Step 2 - Create the Service Principal
########################################
Write-Output "Creating Service Principal: SCuBAGearAutomation and loading certificate thumbprint from $($VMName)"
$SP = New-AzADServicePrincipal -DisplayName SCuBAGearAutomation -CertValue $keyValue -EndDate $EndDate -StartDate $StartDate
$ServicePrincipalID = $SP.ID

# Update Variables used to connect to Microsoft Graph when running SCuBAGear
Write-Output "Updating Variables on $($AutoAccountName) Automation Account, these are used to connect to Microsoft Graph when running SCuBAGear on $($VMName) VM"
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'ClientID' -Value ($SP).AppID -Encrypted $True
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'TenantID' -Value ($SP).AppOwnerOrganizationID -Encrypted $True
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'CertThumbprint' -Value $Thumbprint -Encrypted $True

# Assign appropriate graph permissions to the service principal and add to global readers
function Add-GraphApiRoleToSP {
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$ApplicationName,

        [parameter(Mandatory = $true)]
        [string[]]$GraphApiRole,

        [parameter(mandatory = $true)]
        [string]$Token
    )

    $baseUri = 'https://graph.microsoft.com/v1.0/servicePrincipals'
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $spSearchFiler = '"displayName:{0}" OR "appId:{1}"' -f $ApplicationName, $graphAppId

    try {
        $msiParams = @{
            Method  = 'Get'
            Headers = @{Authorization = "Bearer $Token"; ConsistencyLevel = "eventual" }
        }
        $msiParams.Uri = '{0}?$search={1}' -f $baseUri, $spSearchFiler
        $spList = (Invoke-RestMethod @msiParams).Value
        $msiId = ($spList | Where-Object { $_.displayName -eq $ApplicationName }).Id
        $graphId = ($spList | Where-Object { $_.appId -eq $graphAppId }).Id
        $msiParams.Uri = "$($baseUri)/$($msiId)?`$expand=appRoleAssignments"
        $msiItem = Invoke-RestMethod @msiParams

        $msiParams.Uri = "$baseUri/$($graphId)/appRoles"
        $graphRoles = (Invoke-RestMethod @msiParams).Value | 
        Where-Object { $_.value -in $GraphApiRole -and $_.allowedMemberTypes -Contains "Application" } |
        Select-Object allowedMemberTypes, id, value

        foreach ($roleItem in $graphRoles) {
            if ($roleItem.id -notIn $msiItem.appRoleAssignments.appRoleId) {
                Write-Host "Adding role ($($roleItem.value)) to identity: $($ApplicationName).." -ForegroundColor Green
                $postBody = @{
                    "principalId" = $msiId
                    "resourceId"  = $graphId
                    "appRoleId"   = $roleItem.id
                }
                $postParams = @{
                    Method      = 'Post'
                    Uri         = "$baseUri/$graphId/appRoleAssignedTo"
                    Body        = $postBody | ConvertTo-Json
                    Headers     = $msiParams.Headers
                    ContentType = 'Application/Json'
                }
                $result = Invoke-RestMethod @postParams
                if ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
                    $result
                }
            }
            else {
                Write-Host "role ($($roleItem.value)) already found in $($ApplicationName).." -ForegroundColor Yellow
            }
        }
        
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}
#endregion

# Non-Interactive Permission Requirements - https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md
$roles = @(
    "Directory.Read.All", #Entra ID
    "GroupMember.Read.All", #Entra ID
    "Organization.Read.All", #Entra ID
    "Policy.Read.All", #Entra ID
    "RoleManagement.Read.Directory", #Entra ID
    "User.Read.All", #Entra ID
    "PrivilegedEligibilitySchedule.Read.AzureADGroup", #Entra ID
    "PrivilegedAccess.Read.AzureADGroup", #Entra ID
    "RoleManagementPolicy.Read.AzureADGroup", #Entra ID
    "Sites.FullControl.All" # SharePoint
)

# Connect MgGraph
Write-Output "Connecting to Microsoft Graph to add Service Principal $($SP.DisplayName) to $($Roles)"
Connect-MgGraph -Scopes EntitlementManagement.Read.All,EntitlementManagement.ReadWrite.All
$token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"

Add-GraphApiRoleToSP -ApplicationName $SP.DisplayName -GraphApiRole $roles -Token $token.Token

# Add Service Principal to the appropriate groups
# https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#service-principal
# Define roles
$roles = @("Global Reader")

# Assign roles
foreach ($role in $roles) {
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$role'"
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $servicePrincipalId -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
}

################################################
# Step 3 - Add the VM to the Hybrid Worker Group
################################################
# Install hybrid worker extension on VM
$VMLocation = $SCuBAVM.Location

$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AutoAccountName`?api-version=2021-06-22&`$expand=properties(`$select=automationHybridServiceUrl)"
$HybridURL = ((Invoke-AzRestMethod -Uri $uri).Content | ConvertFrom-Json).properties.automationHybridServiceUrl
 
# Construct the Registration URL
$Settings = @{
    AutomationAccountURL = $HybridURL
}

# Install the Hybrid Worker extension
Write-Output "Installing Hybrid Worker Extension on $($VmName) VM, this will take 1-2 minutes"
Set-AzVMExtension -ResourceGroupName $RG -VMName $vmName -Location $VMlocation `
    -Name "HybridWorkerExtension" -Publisher "Microsoft.Azure.Automation.HybridWorker" `
    -ExtensionType "HybridWorkerForWindows" -TypeHandlerVersion "1.1" -Settings $Settings `
    -EnableAutomaticUpgrade $true

# Add SCuBA to the Hybrid Worker Group
$HybridGroupName = (Get-AzAutomationHybridWorkerGroup -ResourceGroupName $RG -AutomationAccountName $AutoAccountName).Name
$HybridWorkerParams = @{
    Name = $VM_ID
    AutomationAccountName = $AutoAccountName
    HybridRunbookWorkerGroupName = $HybridGroupName
    VmResourceId = $VmId
    ResourceGroupName = $VMResourceGroup
}
New-AzAutomationHybridRunbookWorker @HybridWorkerParams

Write-Output "Restarting Hybrid Worker Service on $($SCuBAVM.Name) Virtual Machine to jump start hybrid worker connection"
# Add code to restart the service
$Script = @"
    Remove-Item C:\test.txt -Force
    Restart-Service -Name HybridWorkerService -Force    
"@
Invoke-AzVMRunCommand -ResourceGroupName $VMResourceGroup -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptString $Script

##########
# Cleanup
##########
Disconnect-AzAccount
Disconnect-MgGraph
