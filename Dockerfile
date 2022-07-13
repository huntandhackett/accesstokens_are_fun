# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/powershell

# Install prereqs to use container from within VSCode

RUN apt-get update && apt-get install --no-install-recommends -y \
less locales ca-certificates gss-ntlmssp libc6 libgcc1 \
libgssapi-krb5-2 libstdc++6 zlib1g openssh-client && \
apt-get dist-upgrade -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* && \
locale-gen $LANG && \
update-locale

ENV PS_INSTALL_FOLDER=/opt/microsoft/powershell/7-lts POWERSHELL_TELEMETRY_OPTOUT="1" DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 PSModuleAnalysisCachePath=/var/cache/microsoft/powershell/PSModuleAnalysisCache/ModuleAnalysisCache POWERSHELL_DISTRIBUTION_CHANNEL=PSDocker-Ubuntu-20.04

#CMD ["pwsh"]
RUN  pwsh -NoLogo -NoProfile -Command " \$ErrorActionPreference = 'Stop' ; \$ProgressPreference = 'SilentlyContinue' ; while(!(Test-Path -Path \$env:PSModuleAnalysisCachePath)) { Write-Host "'Waiting for $env:PSModuleAnalysisCachePath'" ; Start-Sleep -Seconds 6 ; }" 

# Install MSAL modules. ADAL does not work on .NET core
# RUN pwsh -NoLogo -NoProfile -Command 'Install-Module AzureAD -Force -Confirm:$false'
RUN pwsh -NoLogo -NoProfile -Command 'Install-Module MSAL.PS -Force -Confirm:$false'
