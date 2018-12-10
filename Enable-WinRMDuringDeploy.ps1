
##### IMPORTANT: DO NOT ADD PARAMs HERE - os_profile custom_data will take care of this
#####     and add the correct values as defaults

#building needs to add the default parameters
#    azSubscriptionId
#    acmeServer (LE_PROD or LE_STAGE)
#    dnsSuffix
#    mgtDNSSuffix
#    winRmRemoteAddress
#    winRmPortHTTP
#    winRmPortHTTPS


##subscription id is as follows: /subscriptions/00000000-0000-0000-0000-000000000000
$azSubscriptionId = @($azSubscriptionId.split("/"))[@($azSubscriptionId.split("/")).count - 1]
if ($null -eq $mgtDNSSuffix -or $mgtDNSSuffix.length -eq 0) {
    $mgtDNSSuffix = $dnsSuffix
}
if (($null -eq $winRmRemoteAddress) -or ($winRmRemoteAddress.length -eq 0)) {
    $winRmRemoteAddress = "LocalSubnet"
}
if (($null -eq $winRmPortHTTP) -or ($winRmPortHTTP -lt 1)) {
    $winRmPortHTTP = 5985
}
if (($null -eq $winRmPortHTTPS) -or ($winRmPortHTTPS -lt 1)) {
    $winRmPortHTTPS = 5986
}
$certDomain = $env:computerName.ToLower() + "." + $mgtDNSSuffix

$schTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers>
<CalendarTrigger>
  <StartBoundary>2018-11-26T15:58:12</StartBoundary>
  <ExecutionTimeLimit>PT6H</ExecutionTimeLimit>
  <Enabled>true</Enabled>
  <RandomDelay>PT12H</RandomDelay>
  <ScheduleByDay>
    <DaysInterval>1</DaysInterval>
  </ScheduleByDay>
</CalendarTrigger>
<BootTrigger>
  <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
  <Enabled>true</Enabled>
  <Delay>PT5M</Delay>
</BootTrigger>
</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-sta -ExecutionPolicy Unrestricted -file C:\AzureData\Manage-PACertificate.ps1 -AZSubscriptionId $AZSubscriptionId -acmeServer $acmeServer -domain $certDomain</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$ManagePACertificatePS1 = @'
Param (
    $AZSubscriptionId,
    $acmeServer,
    $domain)

    Start-Transcript -Path "C:\AzureData\Manage-PACertificate.log"

#Posh-ACME requires >= .net 4.7.1... load backward module on legacy 4.6
if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 394802) {
    if (-not(Get-Module -Name POSH-ACME)) {
        Import-Module -Name Posh-ACME
    }
}
else {
    if (-not(Get-Module -Name POSH-ACME.net46)) {
        Import-Module -Name Posh-ACME.net46
    }
}

Set-PAServer -DirectoryUrl $acmeServer
$azParams = @{
    AZSubscriptionId = $AZSubscriptionId
    AZUseIMDS = $true
}

$leIssuer = "^CN=(Let's Encrypt Authority|Fake LE Intermediate)"

try {
    $paCertificates = @(Get-PACertificate -MainDomain $domain -ErrorAction Ignore)
}
catch {
    $paCertificates = @()
    Write-Host No existing LE certificates found

}

if ($paCertificates.count -eq 0) {
    Write-Host Request new Certificate
    $paCertificates = @(New-PACertificate -Domain $domain -AcceptTOS -DnsPlugin Azure -PluginArgs $azParams -FriendlyName "WinRM Certificate (by Let's Encrypt)" -Install -Verbose)
}

if ($paCertificates.Count -eq 1) {
    #if newew by isn't reached yet, this will output a warning and not do anything
    #see if the certificate is actually still present
    $installedPACertificates = @(Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$domain" -and $_.Issuer -imatch $leIssuer -and $_.Thumbprint -eq $paCertificates[0].Thumbprint})
    if ($installedPACertificates.Count -eq 0) {
        #force renewal to update the certificate
        Write-Host force renewal of certificate as it was not found in cert store
        Submit-Renewal -MainDomain $domain -Force -WarningAction Continue
    }
    else {
        try {
            Write-Host Check for renewal of certificate
            Submit-Renewal -MainDomain $domain -WarningAction Continue
        }
        catch {
            Write-Error "failed to renew certificate for $domain"
        }
    }
    $paCertificates = @(Get-PACertificate -MainDomain $domain -ErrorAction Ignore)
}
if ($paCertificates.Count -gt 1) {
    Write-Host delete outdated certificates
}


if ($paCertificates[0].thumbprint.length -gt 0) {
    #check if WSMan is using correct certificate
    try {
        $wsmanInstance = @(Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address = "*"; Transport = "HTTPS"} -ErrorAction SilentlyContinue)
    }
    catch {
        $wsmanInstance = @()
    }
    if ($wsmanInstance.Count -eq 0) {
        $winrmValueSet = @{Hostname = $domain; CertificateThumbprint = $paCertificates[0].Thumbprint}
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address = "*"; Transport = "HTTPS"} -ValueSet $winrmValueSet
        Write-Host created new winrm/config/listener certificate to thumbrpint $paCertificates[0].Thumbprint
    }
    else {
        if ($wsmanInstance.CertificateThumbprint -ne $paCertificates[0].Thumbprint) {
            Remove-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address = "*"; Transport = "HTTPS"}
            $winrmValueSet = @{Hostname = $domain; CertificateThumbprint = $paCertificates[0].Thumbprint}
            New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address = "*"; Transport = "HTTPS"} -ValueSet $winrmValueSet
            Write-Host updated winrm/config/listener certificate to thumbrpint $paCertificates[0].Thumbprint
        }
        else {
            Write-Host WSMan certificate $wsmanInstance.CertificateThumbprint is current.
        }
    }

    #clean up superseded LE certificates from local store
    $supersededPACerts = @(Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$domain" -and $_.Issuer -imatch $leIssuer -and $_.Thumbprint -ne $paCertificates[0].Thumbprint})
    foreach ($supersededPACert in $supersededPACerts) {
        $supersededPACert | Remove-Item -Force
        Write-Host deleted superseded cert $supersededPACert.Thumbprint
    }

    #make sure the chain is trusted (only required on LE_STAGE
    if ($acmeServer -eq "LE_STAGE") {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($paCertificates[0].FullChainFile)
        if (-not(Test-Certificate -Cert $cert -DNSName $domain -Verbose -Policy SSL -ErrorAction SilentlyContinue)) {
            if (Test-Certificate -Cert $cert -DNSName $domain -Verbose -Policy SSL -AllowUntrustedRoot) {
                $chain = (New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain)
                # Build the certificate chain from the file certificate
                $chain.Build($cert)
                # Return the list of certificates in the chain (the root will be the last one)
                $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
                [System.Security.Cryptography.X509Certificates.StoreName]$storeName = 'Root'
                [System.Security.Cryptography.X509Certificates.StoreLocation]$storeLocation = 'LocalMachine'
                $CertStore = New-Object   System.Security.Cryptography.X509Certificates.X509Store  -ArgumentList  $StoreName, $StoreLocation
                $CertStore.Open('ReadWrite')
                $CertStore.Add($rootCert)
                $CertStore.Close()
                Write-Host Added $rootCert.Subject to Root store
            }
        }
    }
    # certificate can also be used for RDP
    #
    $tsWMIPath = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
    Set-WmiInstance -Path $tsWMIPath -argument @{SSLCertificateSHA1Hash="$($paCertificates[0].thumbprint)"}
    Write-Host set RDP certificate to $paCertificates[0].thumbprint
}

Stop-Transcript
'@


Start-Transcript -Path "C:\AzureData\Enable-WinRMDuringDeploy.Log"

$userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
[string]$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host (get-date -DisplayHint Time) Starting in context UserName: $userName / IsAdmin: $isAdmin


#install ACME package for Let's Encrypt support
if (-not(Get-PackageProvider -Name NuGet -ListAvailable)) {
    Install-PackageProvider -Name NuGet -Scope AllUsers -Force
    Write-Host (get-date -DisplayHint Time) installing NuGet
}
$nugetProvider = Get-PackageProvider -Name NuGet -ListAvailable
if (-not($nugetProvider)) {
    Write-Host (get-date -DisplayHint Time) failed to use/install NuGet - this is really bad
    Write-Host (get-date -DisplayHint Time) ....fail, thank you and good bye
} else {
    write-host (get-date -DisplayHint Time) $nugetProvider.Name version $nugetProvider.version is installed

    #Posh-ACME requires >= .net 4.7.1... load backward module on legacy 4.6
    if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 394802) {
        if (-not(Get-Module -Name Posh-ACME -ListAvailable)) {
            Install-Module -Name Posh-ACME  -Scope AllUsers -Force
            Write-Host (get-date -DisplayHint Time) Installing Posh-ACME
        }
    } else {
        if (-not(Get-Module -Name Posh-ACME.net46 -ListAvailable)) {
            Install-Module -Name Posh-ACME.net46  -Scope AllUsers -Force
            Write-Host (get-date -DisplayHint Time) Installing Posh-ACME.net46
        }
    }
    $acmeModule = (Get-Module -Name Posh-ACME* -ListAvailable)
    if (-not($acmeModule)) {
        Write-Host (get-date -DisplayHint Time) failed to install Posh-ACME - this is really bad
        Write-Host (get-date -DisplayHint Time) ....fail, thank you and good bye
    } else {
        write-host (get-date -DisplayHint Time) $acmeModule.Name version $acmeModule.version is installed

        #enable WinRM for HTTPS use
        If ((Get-Service "WinRM").Status -ne "Running") {
            Set-Service -Name "WinRM" -StartupType Automatic
            Start-Service -Name "WinRM" -ErrorAction Stop
            Write-Host (get-date -DisplayHint Time) Enabled WinRM service
        }
        If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
            Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
            Write-Host (get-date -DisplayHint Time) Enabled PSRemoting
        }
        $basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object {$_.Name -eq "Basic"}
        If (($basicAuthSetting.Value) -eq $false) {
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
            Write-Host (get-date -DisplayHint Time) Set Basic Auth in WinRM
        }
        #winrm over http (for windows admin center / Azure Automation)
        #dont' touch existing rule or Set-WSManQuickConfig in PoSh Extension will fail
        $netFWRulehttp = Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-AZUREVNET"
        if ($netFWRulehttp) {
            Set-NetFirewallRule -InputObject $netFWRulehttp -NewDisplayName "Windows Remote Management (HTTP-In) - Azurue vnet only" -Description "Inbound rule for Windows Remote Management via WS-Management on HTTP. [TCP $WinRmPortHTTP]" -Profile Private, Domain, Public -Direction Inbound -LocalPort $WinRmPortHTTP -Protocol TCP -Action Allow -RemoteAddress $winRmRemoteAddress
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTP - updated rule WINRM-HTTP-In-TCP-AZUREVNET for remote address $winRmRemoteAddress
        } else {
            New-NetFirewallRule -Name "WINRM-HTTP-In-TCP-AZUREVNET" -DisplayName "Windows Remote Management (HTTP-In) - Azurue vnet only" -Description "Inbound rule for Windows Remote Management via WS-Management on HTTPS. [TCP $WinRmPortHTTP]" -Profile Private, Domain, Public -Direction Inbound -LocalPort $WinRmPortHTTP -Protocol TCP -Action Allow -RemoteAddress $winRmRemoteAddress
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTP - added rule WINRM-HTTP-In-TCP-AZUREVNET for remote address $winRmRemoteAddress
        }
        if ((Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP-AZUREVNET").Enabled -eq "false") {
            Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP-AZUREVNET"
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTP - enabled rule WINRM-HTTP-In-TCP-AZUREVNET
        }
        #winrm over https (for ansible et al)
        $netFWRulehttps = Get-NetFirewallRule -Name "WINRM-HTTPS-In-TCP-AZUREVNET"
        if ($netFWRulehttps) {
            Set-NetFirewallRule -InputObject $netFWRulehttps -NewDisplayName "Windows Remote Management (HTTPS-In) - Azurue vnet only" -Description "Inbound rule for Windows Remote Management via WS-Management on HTTPS. [TCP $WinRmPortHTTPS]" -Profile Private, Domain, Public -Direction Inbound -LocalPort $WinRmPortHTTPS -Protocol TCP -Action Allow -RemoteAddress $winRmRemoteAddress
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTPS - updated rule WINRM-HTTPS-In-TCP-AZUREVNET for remote address $winRmRemoteAddress
        } else {
            New-NetFirewallRule -Name "WINRM-HTTPS-In-TCP-AZUREVNET" -DisplayName "Windows Remote Management (HTTPS-In) - Azurue vnet only" -Description "Inbound rule for Windows Remote Management via WS-Management on HTTPS. [TCP $WinRmPortHTTPS]" -Profile Private, Domain, Public -Direction Inbound -LocalPort $WinRmPortHTTPS -Protocol TCP -Action Allow -RemoteAddress $winRmRemoteAddress
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTPS - added rule WINRM-HTTPS-In-TCP-AZUREVNET for remote address $winRmRemoteAddress
        }
        if ((Get-NetFirewallRule -Name "WINRM-HTTPS-In-TCP-AZUREVNET").Enabled -eq "false") {
            Enable-NetFirewallRule -Name "WINRM-HTTPS-In-TCP-AZUREVNET"
            Write-Host (get-date -DisplayHint Time) Open WinRM Firewall Port TCP $WinRmPortHTTPS - enabled rule WINRM-HTTPS-In-TCP-AZUREVNET
        }

        #register LE part as scheduled task (to run in SYSTEM context)
        #this will fetch a certificate and configure the winrm endpoint
        Write-Host (get-date -DisplayHint Time) drop C:\AzureData\Manage-PACertificate.ps1 script and register scheduled task for it
        Set-Content -Path "C:\AzureData\Manage-PACertificate.ps1" -Value $ManagePACertificatePS1 -Force
        Register-ScheduledTask -xml ($schTask | Out-String) -TaskPath "\AzureData\" -TaskName "Manage-PACertificate.ps1" -Force
        Write-Host (get-date -DisplayHint Time) start scheduled task \AzureData\Manage-PACertificate.ps1
        Start-ScheduledTask -TaskPath "\AzureData\" -TaskName "Manage-PACertificate.ps1"
        Write-Host (get-date -DisplayHint Time) sleeping here to give task time to finish
        Start-Sleep -Seconds 130

        #Unregister-ScheduledTask -TaskPath "\AzureData\" -TaskName  "Manage-PACertificate.ps1" -Force

        # $hostENVComputerName = $env:computerName
        # $AlternativeName = @()
        # if ($dnsSuffix.Length -gt 0) {$AlternativeName += $hostENVComputerName.ToLower() + "." + $dnsSuffix}
        # if ($mgtDNSSuffix.Length -gt 0) {$AlternativeName += $hostENVComputerName.ToLower() + "." + $mgtDNSSuffix}
        # $AlternativeName += $hostENVComputerName



        # Write-Host Generate Self-Signed Certificate for $AlternativeName[0]

        # #create non-exportable self-signed certificate. "Server Authentication" only / validity 10 years
        # $Cert = New-SelfSignedCertificate -Subject $AlternativeName[0] -DnsName $AlternativeName `
        #  -NotAfter (Get-Date).AddYears(10) `
        #  -KeyLength 2048 `
        #  -KeyAlgorithm "RSA" `
        #  -Provider "Microsoft Software Key Storage Provider" `
        #  -KeyExportPolicy "NonExportable"`
        #  -HashAlgorithm "sha256" `
        #  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
        #  -CertStoreLocation "cert:\LocalMachine\My" `
        #  -FriendlyName "Self-Signed WinRM Cert"
        # #TPM based
        # #$ -KeyAlgorithm "RSA" -Provider "Microsoft Platform Crypto Provider"

        # $Cert | Out-String





        #set primary DNS suffix at the very end
        Write-Host (get-date -DisplayHint Time) set primary DNS suffix of computer to $dnsSuffix
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "Domain" -Value $dnsSuffix
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name "NV Domain" -Value $dnsSuffix

    }
}
Write-Host (get-date -DisplayHint Time) ...finished
Stop-Transcript
