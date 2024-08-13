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
    if((Get-Module -ListAvailable az.accounts,az.storage).Count -eq '2')
    {
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        Import-Module -Name az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }else{
        # Install and import SCuBAGear module if not already installed and loaded
        Write-Output "Installing Az.Accounts and Az.Storage Modules...."
        Install-Module az.accounts,az.storage -Force -Confirm:$False -WarningAction SilentlyContinue
        Write-Output "Importing Az.Accounts and Az.Storage Modules...."
        Import-Module az.accounts,az.storage -Force -WarningAction SilentlyContinue
    }
}Catch{
    Write-Error -Message $_.Exception
}

# Define some variables for Graph connection and writing to the storage account
$ClientID = Get-AutomationVariable -Name 'ClientID'
$TenantID = Get-AutomationVariable -Name 'TenantID'
$CertificateThumbprint = Get-AutomationVariable -Name 'CertThumbprint'
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
$Org = Get-AutomationVariable -Name 'Org'
$Date= Get-Date -Format FileDateTime
$ContainerName = "scuba-$TenantID-$Date".ToLower()

function Invoke-StorageTransfer {
    Try{
        Write-Output "Service Principal Connected to Azure for writing result to Storage Account"
        $Report = (Get-ChildItem -Path "C:\Users\" | Sort-Object -Descending -Property LastWriteTime | select-object -First 1).Name
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
        
        Try{
            $StorageContainer = New-AzStorageContainer -Name $ContainerName -Context $ctx
            Write-Output "New Azure Blob Container Created for SCuBAGear Results - $StorageContainer"
        }Catch{
            Write-Output"Azure Blob Container Exists"
        }
        
        Try{
            $Items = Get-ChildItem -Path "C:\Users\$Report" -Recurse | Set-AzStorageBlobContent -Container $ContainerName -Context $ctx -WarningAction SilentlyContinue
            Write-Output "The below items have been Uploaded to Azure Blob Storage"

            ForEach($Item in $Items){
                Write-Host"  - $($Item.Name)" -ForegroundColor Green
            }
        }catch{
            Write-Output "Unable to Upload Report to Blob Storage"
        }
    }Catch{
        Write-Error -Message $_.Exception
        Write-Output "Unable to create blob container"
    }
}

Try{
   if((Get-Module -ListAvailable 'SCuBAGear')){
       Write-Output "Importing SCuBAGear Module...."
       Import-Module -Name SCuBAGear -Force

       # This will check for depencies and latest versions
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Initialize-SCuBA -ScubaParentDirectory C:\Users

       Set-Location C:\Users

       # Connect to Azure and Graph using the service principal and certficate thumbprint
       Write-Output "Connecting to Azure"
       Connect-Azaccount -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID
       Write-Output "Connecting to MGGraph...."
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID
       
       If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
           # Only review AAD and don't try to logon interactively to the portal
           
           $Products = @("aad","teams","exo")

           Try{
               if($Products -Contains "teams"){
               Write-Output "Connecting to Teams"
               Connect-MicrosoftTeams -Certificate $CertificateThumbprint -TenantId $TenantID -ApplicationId $ClientID
                }
           }Catch{
               Write-Error $_.Exception
           }
           
           Try{
                if($Products -Contains "exo"){
                    Write-Output "Connecting to Exchange"
                    Connect-ExchangeOnline -CertificateThumbprint $Certificatethumbprint -AppId $ClientID -Organization $Org
                }
           }Catch{
               Write-Error $_.Exception
           }

           Write-Output "Running SCuBAGear Checks...."
           Invoke-ScuBA -ProductNames $Products -OPAPath C:\Users\.scubagear\tools\ -OutPath C:\Users\ -LogIn $False -CertificateThumbprint $CertificateThumbprint -AppId $ClientID -Organization $Org

           Write-Output "Transferring SCuBAGear results to storage"
           Invoke-StorageTransfer

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
       Write-Output "Initializing SCuBAGear (This can take awhile)...."
       Initialize-SCuBA -ScubaParentDirectory C:\Users

       Set-Location C:\Users
       
       # Connect to Azure and Graph using the service principal and certficate thumbprint
       Write-Output "Connecting to Azure"
       Connect-Azaccount -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -ApplicationID $ClientID -TenantID $TenantID
       Write-Output "Connecting to MGGraph...."
       Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientID $ClientID -TenantID $TenantID

        If((Get-MgContext).AppName -eq 'SCuBAGearAutomation'){
        
            $Products = @("aad","teams","exo")

            Try{
                if($Products -Contains "teams"){
                Write-Output "Connecting to Teams"
                Connect-MicrosoftTeams -Certificate $CertificateThumbprint -TenantId $TenantID -ApplicationId $ClientID
                }
            }Catch{
                Write-Error $_.Exception
            }
            
            Try{
                if($Products -Contains "exo"){
                    Write-Output "Connecting to Exchange"
                    Connect-ExchangeOnline -CertificateThumbprint $Certificatethumbprint -AppId $ClientID -Organization $Org
                }
            }Catch{
                Write-Error $_.Exception
            }

            Write-Output "Running SCuBAGear Checks...."
            Invoke-ScuBA -ProductNames $Products -OPAPath C:\Users\.scubagear\tools\ -OutPath C:\Users\ -LogIn $False -CertificateThumbprint $CertificateThumbprint -AppId $ClientID -Organization $Org

            Write-Output "Transferring SCuBAGear results to storage"
            Invoke-StorageTransfer

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
