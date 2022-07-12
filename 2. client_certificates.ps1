function Import-AppCert {
    # Set to true when a pfx should be used instead of certificate store.
    # Add path to pfx and pfx password
    $usePfx = $false
    $pwd      = '' # Dont store cleartext creds incode peepz.
    $certPath = ''

    # Load certificate
    if (-not $usePfx) { 
        # Retrieve cert from user store
        $clientCertificate = Get-Item -Path "Cert:\CurrentUser\My\$($certThumbprint)"
    }
    else {
        # Import from pfx file
        $clientCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certPath, $pwd
    }

    return $clientCertificate
}

# Install-Module MSAL.PS
# Install-Module AzureAD

$appID          = $script:proxyApp.appID
$tenantID       = $script:proxyApp.tenantId
$certThumbprint = $script:proxyApp.certThumbprint


# Import client certificate
$clientCertificate = Import-AppCert

######################
##        MSAL      ##
######################
Import-Module MSAL.PS
$msalToken = Get-MsalToken -Scope 'https://graph.microsoft.com/.default' -ClientId $appID -ClientCertificate $clientCertificate -TenantId $tenantID
Write-Output "[+] Got token using MSAL and client certificate: $($msalToken.AccessToken)"


######################
##        ADAL      ##
######################
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Error -Message "This does not work on .NET Core"
} else {

    $aZADmodulePath = (Get-Module AzureAD -ListAvailable).ModuleBase
    $azADdll        = Join-Path -Path $aZADmodulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    [void]([System.Reflection.Assembly]::LoadFrom($azADdll))

    $authority   = "https://login.microsoftonline.com/$($tenantID)"
    $authContext = ([Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority))
    $certificateCredential = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate `
                                        -ArgumentList ($appId, $clientCertificate)

    $authResult = $authContext.AcquireTokenAsync('https://graph.microsoft.com', $certificateCredential)
    $authResult.Wait()
    $adalToken = $authResult.Result

    Write-Output "[+] Got token using ADAL and client certificate: $($adalToken.AccessToken)"
}