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
    if((Get-Module az,az.storage).Count -eq '2')
    {
        Write-Output "Importing Az and Az.Storage Modules...."
        Import-Module -Name az,az.storage -Force -WarningAction SilentlyContinue
    }else{
        # Install and import SCuBAGear module if not already installed and loaded
        Write-Output "Installing Az and Az.Storage Modules...."
        Install-Module az,az.storage -Force -Confirm:$False -WarningAction SilentlyContinue
        Write-Output "Importing Az and Az.Storage Modules...."
        Import-Module az,az.storage -Force -WarningAction SilentlyContinue
    }
}Catch{
    Write-Error -Message $_.Exception
}
function Invoke-StorageTransfer {
    Try{
        Connect-Azaccount -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID
        Write-Output "Service Principal Connected to Azure for writing result to Storage Account"
        $Report = (Get-ChildItem -Path "C:\Users\" | Sort-Object -Descending -Property LastWriteTime | select-object -First 1)
        Write-Output "Retrieved Name of SCuBA Directory"
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        Write-Output "Preparing for Connecting to Storage Account"
        Try{
            New-AzStorageContainer -Name $ContainerName -Context $ctx
            Write-Output "Azure Blob Container Created"
        }Catch{
            Write-Output"Azure Blob Container Exists"
        }
        
        Try{
            Get-ChildItem -Path "C:\Users\$Report" -Recurse | Set-AzStorageBlobContent -Container $ContainerName -Context $ctx -WarningAction SilentlyContinue
            Write-Output "Report Uploaded to Azure Blob Storage"
        }catch{
            Write-Output "Unable to Upload Report to Blob Storage"
        }
    }Catch{
        Write-Error -Message $_.Exception
        Write-Output "Storage Messed Up"
    }
}

Try{
   if((Get-Module -ListAvailable 'SCuBAGear')){
        Write-Output "Importing SCuBAGear Module...."
       Import-Module -Name SCuBAGear -Force

       # This will check for depencies and latest versions
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Initialize-SCuBA -ScubaParentDirectory C:\Users

       Copy-Item -Path C:\Windows\System32\config\systemprofile\.scubagear\ -Destination C:\Users\ -Recurse -Force
       Set-Location C:\Users

       # Define some variables for Graph connection and writing to the storage account
       $ClientID = Get-AutomationVariable -Name 'ClientID'
       $TenantID = Get-AutomationVariable -Name 'TenantID'
       $CertificateThumbprint = Get-AutomationVariable -Name 'CertThumbprint'
       $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
       $Date= Get-Date -Format FileDateTime
       $ContainerName = "scuba-$TenantID-$Date".ToLower()

       # Connect to Graph using the service principal and certficate thumbprint
       Write-Output "Connecting to MGGraph...."
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID

       If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
           # Only review AAD and don't try to logon interactively to the portal
           Write-Output "Running SCuBAGear Checks...."
           Invoke-ScuBA -ProductNames aad -OPAPath C:\Users\.scubagear\tools\ -OutPath C:\Users\ -LogIn $False

           # Disconnect from graph
           Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted
           Disconnect-MgGraph

           Invoke-StorageTransfer
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
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Initialize-SCuBA -ScubaParentDirectory C:\Users

       Copy-Item -Path C:\Windows\System32\config\systemprofile\.scubagear\ -Destination C:\Users\ -Recurse -Force
       Set-Location C:\Users
       
       # Define some variables for Graph connection
       $ClientID = Get-AutomationVariable -Name 'ClientID'
       $TenantID = Get-AutomationVariable -Name 'TenantID'
       $CertificateThumbprint = Get-AutomationVariable -Name 'CertThumbprint'

       # Connect to Graph using the service principal and certficate thumbprint
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID

       If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
           # Only review AAD and don't try to logon interactively to the portal
           Write-Output "Running SCuBAGear Checks...."
           Invoke-ScuBA -ProductNames aad -OPAPath C:\Users\.scubagear\tools\ -OutPath C:\Users\ -LogIn $False

           # Disconnect from graph
           Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted
           Disconnect-MgGraph

           Invoke-StorageTransfer
       }else{
           Write-Error "Graph Context is wrong....(Get-MgContext).AppName"
       }
   }
}Catch{
   Write-Error -Message $_.Exception
}
