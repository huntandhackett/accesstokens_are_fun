function Send-Mail ($from, $to, $subject, $htmlbody, $token, $attachmentPath = $null) {

    $Uri     = "https://graph.microsoft.com/v1.0/users/$from/sendMail"

    # Compose body
    $msg =            @{
        "message" = @{
            "subject" = $subject
            "body"    = @{
                "contentType" = 'HTML' 
                "content"     = $htmlbody 
            }      
            "toRecipients" = @(
            @{
                "emailAddress" = @{"address" = $to }
            })          
        }
    }

     # Do we need to send an attachment?
    if (-not [string]::IsNullOrEmpty($attachmentPath)){
        if (-not (Test-Path $attachmentPath)){
            Write-Output "File '$($attachmentPath)' not found. Message not send."
            return
        }
    
        $fname = Get-Item $attachmentPath

        # Add json node for attachment
        $ContentBase64 = [convert]::ToBase64String( [system.io.file]::readallbytes($attachmentPath))
        $attachments = @(
                @{
                    "@odata.type" = "#microsoft.graph.fileAttachment"
                    "name" = $fname.Name
                    "contentType" = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    "contentBytes" = $ContentBase64 
                }
            )
        
        $msg.message.Add("attachments", $attachments)
    }

    $body = $msg | ConvertTo-JSON -Depth 100

    # Send the message
    Invoke-RestMethod -body $body -URI $Uri -Method POST -UseBasicParsing -Headers @{
        'Authorization' = "Bearer $token"
        'Content-Type' = 'application/json'
    }
}

function Get-AuthCode ($port = 9999) {
    # Http Server
    $http = [System.Net.HttpListener]::new() 

    # Hostname and port to listen on
    $http.Prefixes.Add("http://localhost:$($port)/")

    # Start the Http Server 
    $http.Start()

    $gotCode = $false
    $code    = ''
    # Log ready message to terminal 
    if ($http.IsListening) {
        write-host "HTTP server started, waiting for incoming request"
    }

    # Listen for new incoming HTTP requests
    while ($http.IsListening -and (-not $gotCode)) {

        $context = $http.GetContext()

        # Aaanndd there's the auth code
        if ($context.Request.HttpMethod -eq 'GET' -and $context.Request.RawUrl.StartsWith('/?code=')){
            $code = $context.Request.RawUrl.split('=')[1].Split('&')[0]
            $gotCode = $true

            # Let the user know that we received the code
            [string]$response = "<h2> Authorization code received. You can close this webpage and return to the Powershell console</h2>" 

            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response) 
            $context.Response.ContentLength64 = $buffer.Length
            $context.Response.OutputStream.Write($buffer, 0, $buffer.Length) 
            $context.Response.OutputStream.Close() 
        }
    }

    $http.Stop()
    return $code
}

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

function Get-SignedAssertionWithLocalCertificate($clientCertificate, $proxyAppId, $tenantID) {
    # See example: Manually request token with certificate

    # In the example we create a signed JWT token and use that to request an access token. 
    # We skip the request for the access token and just return the signed JWT token

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
        'iss' = $proxyAppId         # The AppID for which we request a token for
        'jti' = [guid]::NewGuid()   # Random GUID
        'nbf' = $NotBefore          # This should not be used before this timestamp
        'sub' = $proxyAppId         # Subject
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

    return $signedJWT
}

function Get-AccessTokenOnBehalf ($signedJWT, $proxyAppId, $tenantID){

    # construct URI to request authorization code
    $uri =  "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/authorize?" + 
            "client_id=$proxyAppId" + 
            "&redirect_uri=http://localhost:9999" +
            "&scope=https%3a%2f%2fvault.azure.net%2fuser_impersonation"  + 
            "&response_type=code" + 
            "&response_mode=query" + 
            "&state=state123"
    
    Write-Host "[+] Go to the following URL and follow the needed steps:"
    Write-Host "$uri"

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $uri | clip
        $authCode = Get-AuthCode
    } else {
        $authCode = Read-Host -Prompt "Paste authorization code"
    }


    # Use authorization code to request an access token for the proxy app
    $headers  = @{"Content-Type" = "application/x-www-form-urlencoded"}
    $response = Invoke-RestMethod -Method POST -URI "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token" -Headers $headers -Body ([ordered]@{
        "client_id"    = $proxyAppId
        "code"         = $authCode
        "redirect_uri" = "http://localhost:9999"
        "grant_type"   = "authorization_code"
        "client_assertion_type" = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        "client_assertion"      = $signedJWT
    })

    return $response.access_token
}

function Get-SignedAccessTokenWithAzureKeyVault ($AKVCertificate, $proxyAppToken, $tenantID, $permissionAppID) {
     
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

    return $response.access_token
}

function Get-AKVCertificate($kvURI, $proxyAppToken, $keyName) {

    # Use whatever logic you want to retrieve the certificate
    $uri = "$($kvURI)/certificates?api-version=7.3"
    $httpResponse = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{ 'Authorization' = "Bearer $($proxyAppToken)" }
    $certs    = $httpResponse.Content | ConvertFrom-Json
    $certUri  = $certs.Value | where {$_.id -like "*$($keyName)*"}

    # Retrieve certificate object
    $httpResponse = Invoke-WebRequest -UseBasicParsing -Uri "$($certUri.id)?api-version=7.3" -Headers @{ 'Authorization' = "Bearer $($proxyAppToken)" }
    return $httpResponse.Content | ConvertFrom-Json
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

###############################################################################
##        Get a signed assertion using local certificate                      #
###############################################################################
$clientCert = Import-AppCert
$signedJwt  = Get-SignedAssertionWithLocalCertificate -clientCertificate $clientCert -proxyAppId $proxyAppId -tenantID $tenantID 

###############################################################################
##        Get an access token using client code flow                          #
###############################################################################
$proxyAccessToken = Get-AccessTokenOnBehalf -signedJWT $signedJwt -proxyAppId $proxyAppId -tenantID $tenantID

###############################################################################
##        Use proxyAccesstoken token to enumerate key vault                   #
###############################################################################
$AKVCertificate = Get-AKVCertificate -kvURI $kvURI -proxyAppToken $proxyAccessToken -keyName $keyName

###############################################################################
##        Get a new access token for App-Permission using the keyvault        #
###############################################################################
$privilegedAccessToken = Get-SignedAccessTokenWithAzureKeyVault -AKVCertificate $AKVCertificate -proxyAppToken $proxyAccessToken -tenantID $tenantID -permissionAppID $permissionAppID  

# Send the mail
Send-Mail -MsgFrom 'malicia@pwncorp.org' -to 'hunter@pwnorp.org' -subject 'It works!' -htmlbody '<h2>It works!</h2>' -token $privilegedAccessToken