function Import-AppCert {
    # Set to true when a pfx should be used instead of certificate store.
    # Add path to pfx and pfx password
    $usePfx = $true
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

function Get-AKVCertificate($kvURI, $proxyAppToken, $keyName) {

    # Use whatever logic you want to retrieve the certificate
    $uri = "$($kvURI)/certificates?api-version=7.3"
    $httpResponse = Invoke-WebRequest -Uri $uri -Headers @{ 'Authorization' = "Bearer $($proxyAppToken)" }
    $certs    = $httpResponse.Content | ConvertFrom-Json
    $certUri  = $certs.Value | where {$_.id -like "*$($keyName)*"}

    # Retrieve certificate object
    $httpResponse = Invoke-WebRequest -Uri "$($certUri.id)?api-version=7.3" -Headers @{ 'Authorization' = "Bearer $($proxyAppToken)" }
    return $httpResponse.Content | ConvertFrom-Json
}

function New-AccessToken ($clientCertificate, $tenantID, $appID, $scope='https://graph.microsoft.com/.default') {

    $audience = "https://login.microsoftonline.com/$($tenantID)/oauth2/token"

    # Create a base64 hash of the certificate. The Base64 encoded string must by urlencoded
    $CertificateBase64Hash = [System.Convert]::ToBase64String($clientCertificate.GetCertHash())
    $CertificateBase64Hash = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    
    # JWT request should be valid for max 2 minutes.
    $StartDate             = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration         = [math]::Round($JWTExpirationTimeSpan,0)
    
    # Create a NotBefore timestamp. 
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore                   = [math]::Round($NotBeforeExpirationTimeSpan,0)
    
    # Create JWT header
    $jwtHeader = @{
        'alg' = "RS256"                   # Use RSA encryption and SHA256 as hashing algorithm
        'typ' = "JWT"                     # We want a JWT
        'x5t' = $CertificateBase64Hash    # Webencoded Base64 of the hash of our certificate
    }
    
    # Create the payload
    $jwtPayLoad = @{
        'aud' = $audience           # Points to oauth token request endpoint for your tenant
        'exp' = $JWTExpiration      # Expiration of JWT request
        'iss' = $appID              # The AppID for which we request a token for
        'jti' = [guid]::NewGuid()   # Random GUID
        'nbf' = $NotBefore          # This should not be used before this timestamp
        'sub' = $appID              # Subject
    }
    
    # Convert header and payload to json and to base64
    $jwtHeaderBytes  = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
    $b64JwtHeader    = [System.Convert]::ToBase64String($jwtHeaderBytes)
    $b64JwtPayload   = [System.Convert]::ToBase64String($jwtPayloadBytes)
    
    # Concat header and payload to create an unsigned JWT
    $unsignedJwt      = $b64JwtHeader + "." + $b64JwtPayload
    $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
    
    # Configure RSA padding and hashing algorithm, load private key of certificate and use it to sign the unsigned JWT
    $privateKey    = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($clientCertificate))
    $padding       = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $signedData    = $privateKey.SignData($unsignedJwtBytes, $hashAlgorithm, $padding)
    
    # Create a signed JWT by adding the signature to the unsigned JWT
    $signature = [Convert]::ToBase64String($signedData) -replace '\+','-' -replace '/','_' -replace '='
    $signedJWT = $unsignedJwt + "." + $signature
    
    # Request an access token using the signed JWT
    $uri      = "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token"
    $headers  = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
        'client_id'             = $appID
        'client_assertion'      = $signedJWT
        'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        'scope'                 = $scope
        'grant_type'            = 'client_credentials'
    })
    
    return $response.access_token
}


$proxyAppId      = $script:proxyApp.appID
$permissionAppID = $script:permissionApp.appID
$certThumbprint  = $script:proxyApp.thumbprint
$tenantID        = $script:proxyApp.tenantId

# URL to keyvault
$kvURI   = 'https://blogpost.vault.azure.net'
$keyName = 'App-WithPermission'

# The target audience for the token for Azure Keyvault is different than we'd normally use for MSGraph
$kvScope = 'https://vault.azure.net/.default'


#####################################################
##        Get token for App-Proxy                   #
#####################################################
$clientCert = Import-AppCert
$proxyAppToken = New-AccessToken -clientCertificate $clientCert -tenantID $tenantID -appID $proxyAppId -scope $kvScope 

#########################################################
##        Use App-Proxy token to enumerate key vault    #
#########################################################
$AKVCertificate = Get-AKVCertificate -kvURI $kvURI -proxyAppToken $proxyAppToken -keyName $keyName

# Create a new assertion with all the information we received from the keyvault. This assertion is then signed and sent to 
# the keyvault to sign the hash. The hash is added to the unsigned assertion, making it a signed one. 
# The signed assertion will be used to request a valid access token
$audience = "https://login.microsoftonline.com/$($tenantID)/oauth2/token"

# JWT request should be valid for max 2 minutes.
$StartDate             = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
$JWTExpiration         = [math]::Round($JWTExpirationTimeSpan,0)

# Create a NotBefore timestamp. 
$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
$NotBefore                   = [math]::Round($NotBeforeExpirationTimeSpan,0)

# Create JWT header
$jwtHeader = @{
    'alg' = "RS256"              # Use RSA encryption and SHA256 as hashing algorithm
    'typ' = "JWT"                # We want a JWT
    'x5t' = $AKVCertificate.x5t  # The pubkey hash we received from Azure Key Vault
}

# Create the payload
$jwtPayLoad = @{
    'aud' = $audience           # Points to oauth token request endpoint for your tenant
    'exp' = $JWTExpiration      # Expiration of JWT request
    'iss' = $permissionAppID    # The AppID for which we request a token for
    'jti' = [guid]::NewGuid()   # Random GUID
    'nbf' = $NotBefore          # This should not be used before this timestamp
    'sub' = $permissionAppID    # Subject
}

# Convert header and payload to json and to base64
$jwtHeaderBytes  = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
$jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
$b64JwtHeader    = [System.Convert]::ToBase64String($jwtHeaderBytes)
$b64JwtPayload   = [System.Convert]::ToBase64String($jwtPayloadBytes)

# Concat header and payload to create an unsigned JWT and compute a Sha256 hash
$unsignedJwt      = $b64JwtHeader + "." + $b64JwtPayload
$unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
$hasher           = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$jwtSha256Hash    = $hasher.ComputeHash($unsignedJwtBytes)
$jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='

# Sign the sha256 of the unsigned JWT using the certificate in Azure Key Vault
$uri      = "$($AKVCertificate.kid)/sign?api-version=7.3"
$headers  = @{
    'Authorization' = "Bearer $proxyAppToken"
    'Content-Type' = 'application/json'
}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered] @{
    'alg'   = 'RS256'
    'value' = $jwtSha256HashB64
}) | ConvertTo-Json)
$signature = $response.value

# Concat the signature to the unsigned JWT
$signedJWT = $unsignedJwt + "." + $signature

# Request an access token using the signed JWT
$uri      = "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token"
$headers  = @{'Content-Type' = 'application/x-www-form-urlencoded'}
$response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
    'client_id'             = $permissionAppID
    'client_assertion'      = $signedJWT
    'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    'scope'                 = 'https://graph.microsoft.com/.default'
    'grant_type'            = 'client_credentials'
})

Write-Output "[+] Got token using REST, Azure Keyvault and client certificates: $($response.access_token)"