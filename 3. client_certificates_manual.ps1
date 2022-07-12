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

$appID          = $script:proxyApp.appID
$tenantID       = $script:proxyApp.tenantId
$certThumbprint = $script:proxyApp.certThumbprint

# Import client certificate
$clientCertificate = Import-AppCert

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
    'scope'                 = 'https://graph.microsoft.com/.default'
    'grant_type'            = 'client_credentials'
})

Write-Output "[+] Got token using REST and client certificate: $($response.access_token)"