# SCuBAGear Automation
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpickax1%2FSCuBAGear_Automation%2Fmain%2FDeploy.json)
[![Deploy To Azure US Gov](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazuregov.svg?sanitize=true)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fpickax1%2FSCuBAGear_Automation%2Fmain%2FDeploy.json)

## Steps to Configure SCuBAGear Automation

### Step 1: Select the blue Deploy to Azure Button
- Create a new resource group
- Select an automation region
- Set VM password

### Step 2: Download and Run the [`Invoke-AfterARMDeployment.ps1`](https://raw.githubusercontent.com/Pickax1/SCuBAGear_Automation/main/Invoke-AfterARMDeployment.ps1) Script
- This script will need to be ran with a highly privledged account I.E Global Admin
- You will only need to provide the below items
    - Input the resource group you created in Step 1
    - Authenticate to Azure and Microsoft Graph, codes with URL will apear when running the script
- The script sets the below
    - Creates and installes a Self-Signed certificate on the SCuBA Virtual Machine (VM)
    - Creates a Service Principal named (SCuBAGearAutomation) and assigns the permissions listed [Here](https://cisagov.github.io/ScubaGear/docs/prerequisites/noninteractive.html)
    - Saves variables to the automation runbook to pass along during the execution of SCuBAGear
    - Adds the VM to the Hybrid Worker group and installs the Hybrid Worker Extension
    - Installs PowerShell 7 on the VM

### Step 3: Navigate to the Automation Account in Azure
- Under **Process Automation** select **Runbooks**
  - Select the `Run_SCuBAGear` runbook and press **Start**
    - This will run the baselines for (aad, teams, exo, and defender)
    - This runbook runs under PowerShell 7.2 context
  - For run settings, ensure you select **Run on the Hybrid Worker**
- Review the output screen for updates

- Repeat the above steps for `Run_SharePoint` runbook
    -   This will run the SharePoint baseline
    -   This runbook runs under PowerShell 5.1 context  

### Step 4: Verify Files are Saved Within the Storage Container

---

> **NOTE:** You only need to run Steps 1-2 once. These steps must be performed by someone with the correct permissions to create and provision resources within your tenant.
