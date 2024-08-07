<#
    This script will need to be ran after deploying the ARM template located at the below GitHUb repo
      - https://github.com/Pickax1/SCuBAGear_Automation/tree/main

    Steps
    1. Create Self-Signed certificate on SCuBA Virtual Machine (VM)
      - Save the thumbprint, start/end date to variables in the runbook for use authenticating with Microsoft Graph
      - Export the certificate
    2. Create a service principal and associate the certificate and assign the service principal with the correct permissions in order to run SCuBAGear
    3. Add the VM to the hybrid worker group

#>

## Requires Az.Accounts,

Connect-MgGraph

# Define some variables for later use
$SCuBAVM = Get-AzVM -Name SCuBA
$VMResourceGroup = $SCuBAVM.Id.Split('/')[4]
$VmId = $SCuBAVM.Id
$VM_ID = $SCuBAVM.VmId
$VMName = $SCuBAVM.Name
$AutoAccountName = 'scubarunbook'

########################################
# Step 1 - Create the certificate on VM
########################################

# Script to create Self-Signed Certificate
$Script = @"
Try{

    `$SCuBACertParams = @{
        CertStoreLocation = "cert:\LocalMachine\My" # Needed since runbook runs as SYSTEM
        Subject = "CN=SCuBAAutomationCertTest"
        NotAfter = (Get-Date).AddYears(1) # Cert will expire 1 year after issued
    }

    # Create the Self-Signed Certificate and store with the LocalComputer store
    `$cert = New-SelfSignedCertificate @SCuBACertParams
    `$Thumbprint = (`$Cert).Thumbprint
    `$keyValue = [System.Convert]::ToBase64String(`$cert.GetRawCertData())
    `$StartDate = (`$Cert).NotBefore
    `$EndDate = (`$Cert).NotAfter

    # Test
    echo "Thumbprint: `$Thumbprint" >> C:\Users\SCuBA\test.txt
    echo "KeyValue: `$KeyValue" >> C:\Users\SCuBA\test.txt
    echo "StartDate: `$StartDate" >> C:\Users\SCuBA\test.txt
    echo "EndDate: `$EndDate" >> C:\Users\SCuBA\test.txt

    `$FullOutput = GC C:\Users\SCuBA\Test.txt
    return `$FullOutput

    # Cleanup
    Remove-Item C:\Users\SCuBA\test.txt -Force -Confirm:`$False

}Catch{
    Write-Error -Message `$_.Exception
}
"@
# Run the script on the SCuBA VM
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

$SP = New-AzADServicePrincipal -DisplayName SCuBAGearAutomation -CertValue $keyValue -EndDate $EndDate -StartDate $StartDate
$ServicePrincipalID = $SP.ID

# Update Variables used to connect to Microsoft Graph when running SCuBAGear
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'ClientID' -Value ($SP).AppID -Encrypted $False
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'TenantID' -Value ($SP).AppOwnerOrganizationID -Encrypted $False
Set-AzAutomationVariable -AutomationAccountName $AutoAccountName -ResourceGroupName $VMResourceGroup -Name 'CertThumbprint' -Value $Thumbprint -Encrypted $False

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
            Uri     = '{0}?$search={1}' -f $baseUri, $spSearchFiler
            Headers = @{Authorization = "Bearer $Token"; ConsistencyLevel = "eventual" }
        }
        $spList = (Invoke-RestMethod @msiParams).Value
        $msiId = ($spList | Where-Object { $_.displayName -eq $applicationName }).Id
        $graphId = ($spList | Where-Object { $_.appId -eq $graphAppId }).Id
        $msiItem = Invoke-RestMethod @msiParams -Uri "$($baseUri)/$($msiId)?`$expand=appRoleAssignments"

        $graphRoles = (Invoke-RestMethod @msiParams -Uri "$baseUri/$($graphId)/appRoles").Value | 
        Where-Object { $_.value -in $GraphApiRole -and $_.allowedMemberTypes -Contains "Application" } |
        Select-Object allowedMemberTypes, id, value
        foreach ($roleItem in $graphRoles) {
            if ($roleItem.id -notIn $msiItem.appRoleAssignments.appRoleId) {
                Write-Host "Adding role ($($roleItem.value)) to identity: $($applicationName).." -ForegroundColor Green
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
                Write-Host "role ($($roleItem.value)) already found in $($applicationName).." -ForegroundColor Yellow
            }
        }
        
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}
#endregion

#region How to use the function
$TenantID = (Get-AzContext).Tenant.Id
Connect-AzAccount -TenantId $TenantID
$token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$roles = @(
    "Directory.Read.All", 
    "GroupMember.Read.All", 
    "Organization.Read.All", 
    "Policy.Read.All", 
    "RoleManagement.Read.Directory", 
    "User.Read.All"
)
Add-GraphApiRoleToSP -ApplicationName $SP.DisplayName -GraphApiRole $roles -Token $token.Token

# Add Service Principal to the appropriate groups
# Define roles
# https://github.com/cisagov/ScubaGear/blob/main/docs/prerequisites/noninteractive.md#service-principal
$roles = @("Global Reader")

# Assign roles
foreach ($role in $roles) {
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$role'"
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $servicePrincipalId -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
}

################################################
# Step 3 - Add the VM to the Hybrid Worker Group
################################################
$HybridGroupName = (Get-AzAutomationHybridWorkerGroup -ResourceGroupName $VMResourceGroup -AutomationAccountName $AutoAccountName).Name
$HybridWorkerParams = @{
    Name = $VM_ID
    AutomationAccountName = $AutoAccountName
    HybridRunbookWorkerGroupName = $HybridGroupName
    VmResourceId = $VmId
    ResourceGroupName = $VMResourceGroup
}
New-AzAutomationHybridRunbookWorker @HybridWorkerParams

##########
# Cleanup
##########
Disconnect-AzAccount
Disconnect-MgGraph
