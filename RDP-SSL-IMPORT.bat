@echo off
setlocal EnableExtensions
title RDP TLS Certificate Installer
color 0A

echo ============================================================
echo        RDP TLS CERTIFICATE IMPORT AND BINDING TOOL
echo ============================================================
echo.

:: ------------------------------------------------------------
:: Administrator check
:: ------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo.
    pause
    exit /b 1
)

echo [OK] Administrator privileges confirmed.
echo.

:: ------------------------------------------------------------
:: PFX file
:: ------------------------------------------------------------
set "PFXFILE=%~1"

if "%PFXFILE%"=="" (
    set /p "PFXFILE=Enter full path to PFX file: "
)

if not exist "%PFXFILE%" (
    echo.
    echo [ERROR] PFX file not found:
    echo %PFXFILE%
    echo.
    pause
    exit /b 1
)

echo.
echo [INFO] PFX: %PFXFILE%
echo.

:: ------------------------------------------------------------
:: Run secure PowerShell processing
:: ------------------------------------------------------------
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
"$ErrorActionPreference='Stop';" ^
"Write-Host '';" ^
"Write-Host '============================================================' -ForegroundColor Cyan;" ^
"Write-Host ' RDP TLS CERTIFICATE CONFIGURATION' -ForegroundColor Cyan;" ^
"Write-Host '============================================================' -ForegroundColor Cyan;" ^
"Write-Host '';" ^
"$pfxPath='%PFXFILE%';" ^
"try {" ^
"  Write-Host '[1/7] Reading PFX password...' -ForegroundColor Yellow;" ^
"  $pwd=Read-Host 'Enter PFX password' -AsSecureString;" ^
"" ^
"  Write-Host '[2/7] Importing certificate into Local Computer\Personal...' -ForegroundColor Yellow;" ^
"  $cert=Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pwd -Exportable:$false;" ^
"" ^
"  if(-not $cert) { throw 'Certificate import returned no certificate.' };" ^
"" ^
"  Write-Host ('      Subject    : ' + $cert.Subject);" ^
"  Write-Host ('      Issuer     : ' + $cert.Issuer);" ^
"  Write-Host ('      Thumbprint : ' + $cert.Thumbprint);" ^
"  Write-Host ('      Expires    : ' + $cert.NotAfter);" ^
"" ^
"  Write-Host '[3/7] Validating certificate...' -ForegroundColor Yellow;" ^
"" ^
"  if(-not $cert.HasPrivateKey) {" ^
"      throw 'Certificate does not contain a private key.';" ^
"  };" ^
"" ^
"  if($cert.NotAfter -le (Get-Date)) {" ^
"      throw 'Certificate has expired.';" ^
"  };" ^
"" ^
"  $serverAuth=$false;" ^
"  foreach($eku in $cert.EnhancedKeyUsageList) {" ^
"      if($eku.ObjectId.Value -eq '1.3.6.1.5.5.7.3.1') {" ^
"          $serverAuth=$true;" ^
"      };" ^
"  };" ^
"" ^
"  if(-not $serverAuth) {" ^
"      throw 'Certificate does not contain Server Authentication EKU.';" ^
"  };" ^
"" ^
"  Write-Host '      Private key          : YES' -ForegroundColor Green;" ^
"  Write-Host '      Server Authentication: YES' -ForegroundColor Green;" ^
"  Write-Host '      Certificate validity : VALID' -ForegroundColor Green;" ^
"" ^
"  Write-Host '[4/7] Locating RDP-Tcp listener...' -ForegroundColor Yellow;" ^
"" ^
"  $rdp=Get-CimInstance -Namespace 'root/cimv2/TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter \"TerminalName='RDP-tcp'\";" ^
"" ^
"  if(-not $rdp) {" ^
"      throw 'RDP-Tcp listener could not be found.';" ^
"  };" ^
"" ^
"  Write-Host '[5/7] Binding certificate to RDP-Tcp...' -ForegroundColor Yellow;" ^
"" ^
"  Set-CimInstance -InputObject $rdp -Property @{SSLCertificateSHA1Hash=$cert.Thumbprint} | Out-Null;" ^
"" ^
"  Write-Host '[6/7] Enforcing TLS and Network Level Authentication...' -ForegroundColor Yellow;" ^
"" ^
"  $reg='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';" ^
"  Set-ItemProperty -Path $reg -Name 'SecurityLayer' -Type DWord -Value 2;" ^
"  Set-ItemProperty -Path $reg -Name 'UserAuthentication' -Type DWord -Value 1;" ^
"" ^
"  Write-Host '[7/7] Verifying configuration...' -ForegroundColor Yellow;" ^
"" ^
"  $verify=Get-CimInstance -Namespace 'root/cimv2/TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter \"TerminalName='RDP-tcp'\";" ^
"" ^
"  Write-Host '';" ^
"  Write-Host '------------------- RESULT -------------------' -ForegroundColor Cyan;" ^
"  Write-Host ('Server      : ' + $env:COMPUTERNAME);" ^
"  Write-Host ('Certificate : ' + $cert.Subject);" ^
"  Write-Host ('Thumbprint  : ' + $verify.SSLCertificateSHA1Hash);" ^
"  Write-Host ('Expiry      : ' + $cert.NotAfter);" ^
"  Write-Host ('TLS Layer   : ' + $verify.SecurityLayer);" ^
"  Write-Host ('NLA         : ' + $verify.UserAuthenticationRequired);" ^
"  Write-Host '----------------------------------------------';" ^
"" ^
"  if($verify.SSLCertificateSHA1Hash -eq $cert.Thumbprint) {" ^
"      Write-Host '';" ^
"      Write-Host '[PASS] RDP certificate successfully bound.' -ForegroundColor Green;" ^
"  } else {" ^
"      throw 'RDP certificate binding verification failed.';" ^
"  };" ^
"" ^
"  Write-Host '';" ^
"  Write-Host 'SecurityLayer 2 = TLS enforced' -ForegroundColor Green;" ^
"  Write-Host 'NLA             = Enabled' -ForegroundColor Green;" ^
"} catch {" ^
"  Write-Host '';" ^
"  Write-Host ('[FAILED] ' + $_.Exception.Message) -ForegroundColor Red;" ^
"  exit 1;" ^
"}"

if %errorlevel% neq 0 (
    echo.
    echo ============================================================
    echo                    CONFIGURATION FAILED
    echo ============================================================
    pause
    exit /b 1
)

echo.
echo ============================================================
echo                 RDP TLS CONFIGURATION COMPLETE
echo ============================================================
echo.
echo IMPORTANT:
echo Restarting Remote Desktop Services will disconnect
echo any active RDP sessions.
echo.
choice /C YN /N /M "Restart Remote Desktop Services now? [Y/N]: "

if errorlevel 2 goto norestart
if errorlevel 1 goto restart

:restart
echo.
echo [INFO] Restarting Remote Desktop Services...
net stop TermService /y
net start TermService

if %errorlevel% neq 0 (
    echo [WARNING] Service restart had an issue.
    echo A server reboot will apply the configuration.
) else (
    echo [OK] Remote Desktop Services restarted.
)
goto end

:norestart
echo.
echo [INFO] Service restart skipped.
echo Reboot the server during your maintenance window.

:end
echo.
echo ============================================================
echo Verify RDP using the SERVER FQDN matching the certificate.
echo Example: SERVER01.company.local
echo ============================================================
echo.
pause

endlocal
