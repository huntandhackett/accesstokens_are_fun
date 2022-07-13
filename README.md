# About this repository
Repository containing examples to play with access tokens and JWTs
Link to blogpost: https://www.huntandhackett.com/blog/researching-access-tokens-for-fun-and-knowledge

Repository contains 5 examples: 
  1. Request access token using client secrets using MSAL, ADAL and REST API 
  2. Request access token using client certificates using MSAL and ADAL 
  3. Request access token by constructing and signing the JWT manually using a local certificate 
  4. Request access token by constructing the JWT manually and sign it using Azure Key Vault. An application is used for authentication 
  5. Request access token by constructing the JWT manually and sign it using Azure Key Vault. An application as well as a user account is used for authentication. 
  
 A Dockerfile is provided that runs PowerShell core and installs the MSAL module. For optimal experience, run the examples in a desktop environment.
