Try{
    Write-Output "Setting PSGallary to trusted...."
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
}Catch{
    Write-Error -Message $_.Exception
}

Try{
   if((Get-PackageProvider -Name 'NuGet')){
       # NuGet is installed
       Write-Output "NuGet provider is installed...."
   }Else{
       # NuGet wasn't installed, installing now
       Write-Output "Installing NuGet provider...."
       Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
   }
}Catch{
   Write-Error -Message $_.Exception
}

Try{
   if((Get-Module -ListAvailable 'SCuBAGear')){
        Write-Output "Importing SCuBAGear Module...."
       Import-Module -Name SCuBAGear -Force

       # This will check for depencies and latest versions
       Set-Location C:\Users\SCuBA\
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Initialize-SCuBA

       # Change directory to where the OPA executable was downloaded/located at
       Set-Location .\.scubagear\tools

       # Define some variables for Graph connection
       $ClientID = Get-AutomationVariable -Name 'ClientID'
       $TenantID = Get-AutomationVariable -Name 'TenantID'
       $CertificateThumbprint = Get-AutomationVariable -Name 'CertThumbprint'

       # Connect to Graph using the service principal and certficate thumbprint
       Write-Output "Connecting to MGGraph...."
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID

       If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
           # Only review AAD and don't try to logon interactively to the portal
           Write-Output "Running SCuBAGear Checks...."
           Invoke-ScuBA -ProductNames aad -LogIn $False

           # Move generated folder and files to SCuBA users directory
           Write-Output "Moving results to SCuBA directory...."
           Copy-Item -Recurse -Path C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows\*\HybridWorkerPackage\HybridWorkerAgent\M365BaselineConformance* -Destination C:\Users\SCuBA\

           # Disconnect from graph
           Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted
           Disconnect-MgGraph

       }else{
           Write-Error "Graph Context is wrong....(Get-MgContext).AppName"
       }
   }else{
       # Install and import SCuBAGear module if not already installed and loaded
       Write-Output "Installing SCuBAGear Module...."
       Install-Module SCuBAGear -Force -Confirm:$False
       Write-Output "Importing SCuBAGear Module...."
       Import-Module SCuBAGear -Force

       # This will check for depencies and latest versions
       Set-Location C:\Users\SCuBA\
       Write-Output "Initializing SCuBAGear...."
       Initialize-SCuBA

       # Change directory to where the OPA executable was downloaded/located at
       Set-Location .\.scubagear\tools

       # Define some variables for Graph connection
       $ClientID = Get-AutomationVariable -Name 'ClientID'
       $TenantID = Get-AutomationVariable -Name 'TenantID'
       $CertificateThumbprint = Get-AutomationVariable -Name 'CertThumbprint'

       # Connect to Graph using the service principal and certficate thumbprint
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID

       If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
           # Only review AAD and don't try to logon interactively to the portal
           Write-Output "Running SCuBAGear Checks...."
           Invoke-ScuBA -ProductNames aad -LogIn $False

           # Move generated folder and files to SCuBA users directory
           Write-Output "Moving results to SCuBA directory...."
           Copy-Item -Recurse -Path C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows\*\HybridWorkerPackage\HybridWorkerAgent\M365BaselineConformance* -Destination C:\Users\SCuBA\

           # Disconnect from graph
           Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted
           Disconnect-MgGraph

       }else{
           Write-Error "Graph Context is wrong....(Get-MgContext).AppName"
       }
   }
}Catch{
   Write-Error -Message $_.Exception
}
