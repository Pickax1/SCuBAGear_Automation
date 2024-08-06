Try{
    If((Get-ChildItem Cert:\LocalMachine\My\$(Get-AutomationVariable -Name 'CertThumbprint'))){
        $Params = @{
        CertStoreLocation = "cert:\LocalMachine\My" # Needed since runbook runs as SYSTEM
        Subject = "CN=SCuBAAutomationCertTest"
        NotAfter = (Get-Date).AddYears(1) # Cert will expire 1 year after issued
        }

        # Create self-signed certificate and store some values
        $cert = New-SelfSignedCertificate @Params
        $Thumbprint = ($Cert).Thumbprint
        $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

        # Update Variables
        New-AutomationVariable -Name 'CertThumbprint' -Value $Thumbprint
        New-AutomationVariable -Name 'StartDate' -Value ($Cert).NotBefore
        New-AutomationVariable -Name 'EndDate' -Value ($Cert).NotAfter
        New-AutomationVariable -Name 'KeyValue' -Value $keyValue
    }else{
        # Certificate is loaded
        Write-OutPut "Certificate is loaded..."
    }

}Catch{
    Write-Error -Message $_.Exception
}
