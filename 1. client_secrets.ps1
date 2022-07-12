# Install-Module MSAL.PS
# Install-Module AzureAD

$appID        = $script:proxyApp.appID
$secret       = $script:proxyApp.secret
$sSecret      = (ConvertTo-SecureString $secret -AsPlainText -Force)
$tenantID     = $script:proxyApp.tenantId

######################
##        MSAL      ##
######################
Import-Module MSAL.PS
$msalToken = Get-MsalToken -ClientId $appID -ClientSecret $sSecret `
                -TenantId $tenantID -Scope 'https://graph.microsoft.com/.default'

Write-Output "[+] Got token using MSAL and client secret: $($msalToken.AccessToken)"

######################
##        ADAL      ##
######################
if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Error -Message "This does not work on .NET Core"
} else {

    $aZADmodulePath = (Get-Module AzureAD -ListAvailable).ModuleBase
    $azADdll        = Join-Path -Path $aZADmodulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    [void]([System.Reflection.Assembly]::LoadFrom($azADdll))

    $authority        = "https://login.microsoftonline.com/$($tenantID)"
    $authContext      = ([Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority))
    $clientCredential = New-Object  -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential `
                                    -ArgumentList ($appId, $secret)

    $authResult = $authContext.AcquireTokenAsync('https://graph.microsoft.com', $clientCredential)
    $authResult.Wait()
    $adalToken = $authResult.Result

    Write-Output "[+] Got token using ADAL and client secret: $($adalToken.AccessToken)"
}


######################
##      Using REST  ##
######################
$uri      = "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token"
$headers  = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
    'client_id'     = $appID
    'scope'         = 'https://graph.microsoft.com/.default'
    'client_secret' = $secret
    'grant_type'    = 'client_credentials'
})

$restToken = $response
Write-Output "[+] Got token using REST and client secret: $($restToken.access_token)"