# Requires -RunAsAdministrator

param(
    [string]$Service = "",
    [int]$Port = 0,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)

# ==============================================================================
# UTILS & LOGGING
# ==============================================================================

function Write-LogInfo ([string]$Message) {
    Write-Host "[INFO] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Cyan
}

function Write-LogSuccess ([string]$Message) {
    Write-Host "[OK]   $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Green
}

function Write-LogWarn ([string]$Message) {
    Write-Host "[WARN] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Yellow
}

function Write-LogError ([string]$Message) {
    Write-Host "[FAIL] $(Get-Date -Format 'HH:mm:ss') - $Message" -ForegroundColor Red
}

function Validate-Input {
    param([string]$InputData)
    if ([string]::IsNullOrWhiteSpace($InputData)) { return $false }
    if ($InputData -match '[\<\>\:\"\\\/\|\?\*]') { return $false }
    return $true
}

function Test-PortInRange {
    param([int]$Port)
    return ($Port -ge 1 -and $Port -le 65535)
}

function Test-PortInUse {
    param([int]$Port)
    $tcp = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    $udp = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue
    return ([bool]$tcp -or [bool]$udp)
}

# ==============================================================================
# DYNAMIC VERSIONING
# ==============================================================================

function Get-DynamicVersions {
    param([string]$Service)
    
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-LogWarn "Chocolatey no encontrado. Instalando..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }

    $versions = @()
    switch ($Service.ToLower()) {
        "iis" {
            $build = [System.Environment]::OSVersion.Version.Build
            $ver = if ($build -ge 20348) { "10.0 (Win2022)" } elseif ($build -ge 17763) { "10.0 (Win2019)" } else { "10.0" }
            return @($ver)
        }
        "apache" {
            $chocoOut = choco search apache-httpd --exact --all-versions | Select-String "apache-httpd\s+\d"
            foreach ($line in $chocoOut) {
                $parts = $line.ToString().Trim() -split '\s+'
                if ($parts.Count -ge 2) { $versions += $parts[1] }
            }
        }
        "nginx" {
            $chocoOut = choco search nginx --exact --all-versions | Select-String "nginx\s+\d"
            foreach ($line in $chocoOut) {
                $parts = $line.ToString().Trim() -split '\s+'
                if ($parts.Count -ge 2) { $versions += $parts[1] }
            }
        }
    }
    
    if ($versions.Count -eq 0) {
        if ($Service -eq "apache") { return @("2.4.58", "2.4.55") }
        if ($Service -eq "nginx") { return @("1.27.4", "1.26.3") }
    }
    return $versions | Select-Object -First 5
}

# ==============================================================================
# SECURITY & PERMISSIONS
# ==============================================================================

function Apply-IISHardening {
    Import-Module WebAdministration
    $header = Get-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." | Where-Object { $_.Name -eq "X-Powered-By" }
    if ($header) {
        Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "X-Powered-By" -ErrorAction SilentlyContinue
    }
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpProtocol/customHeaders" -name "." -value @{name='X-Frame-Options';value='SAMEORIGIN'} -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpProtocol/customHeaders" -name "." -value @{name='X-Content-Type-Options';value='nosniff'} -ErrorAction SilentlyContinue
}

function Set-ServicePermissions {
    param([string]$ServiceName, [string]$Path)
    $User = "svc_$ServiceName"
    if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        $Pass = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
        New-LocalUser -Name $User -Password $Pass -Description "Dedicated Service User" | Out-Null
    }
    if (-not (Test-Path $Path)) {
        Write-LogWarn "No se pudo aplicar permisos: La ruta $Path no existe."
        return
    }
    $acl = Get-Acl $Path -ErrorAction SilentlyContinue
    if ($null -eq $acl) { 
        Write-LogWarn "No se pudo obtener el ACL para $Path."
        return 
    }
    $acl.SetAccessRuleProtection($true, $true)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($User, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $Path $acl
}

function Set-HttpFirewallRule {
    param([int]$Port, [string]$Svc)
    $Name = "HTTP-Allow-$Svc-$Port"
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $Name -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    }
}

# ==============================================================================
# INSTALLATION LOGIC
# ==============================================================================

function Generate-IndexHtml {
    param([string]$Path, [string]$Svc, [string]$Ver, [int]$Port)
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    @"
<!DOCTYPE html>
<html>
<head><title>Servidor $Svc</title><style>body { font-family: sans-serif; text-align: center; background: #f4f4f4; padding: 50px; }</style></head>
<body><div style="background: white; padding: 20px; border-radius: 10px; display: inline-block;">
    <h1>Servidor: $Svc</h1><p><strong>Version:</strong> $Ver</p><p><strong>Puerto:</strong> $Port</p><hr><p><small>Aprovisionado: $Time</small></p>
</div></body></html>
"@ | Set-Content -Path $Path -Encoding UTF8
}

function Install-WebServer {
    param([string]$Service, [int]$Port, [string]$Version)
    Write-LogInfo "Iniciando instalacion de $Service ($Version) en puerto $Port..."
    
    switch ($Service.ToLower()) {
        "iis" {
            $features = @("IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-DefaultDocument", "IIS-StaticContent", "IIS-RequestFiltering")
            foreach ($f in $features) { Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null }
            Import-Module WebAdministration
            Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName BindingInformation -Value "*:$($Port):" -ErrorAction SilentlyContinue
            Apply-IISHardening
            Set-ServicePermissions -ServiceName "iis" -Path "C:\inetpub\wwwroot"
            Generate-IndexHtml -Path "C:\inetpub\wwwroot\index.html" -Svc "IIS" -Ver $Version -Port $Port
            Start-Service W3SVC
        }
        "nginx" {
            Write-LogInfo "Ejecutando choco install nginx..."
            choco install nginx --version=$Version -y --no-progress
            
            # Intentar detectar la ruta de instalación
            $pathsToCheck = New-Object System.Collections.Generic.List[string]
            $pathsToCheck.Add("C:\tools\nginx")
            $pathsToCheck.Add("$env:SystemDrive\tools\nginx")
            if ($env:ChocolateyToolsLocation) { $pathsToCheck.Add("$env:ChocolateyToolsLocation\nginx") }
            if ($env:ChocolateyInstall) { $pathsToCheck.Add("$env:ChocolateyInstall\lib\nginx\tools\nginx") }
            
            # 1. Intentar detectar vía comando en PATH
            $cmd = Get-Command nginx.exe -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd) {
                $pathsToCheck.Insert(0, (Split-Path -Path $cmd.Definition -Parent))
            }

            # 2. Intentar detectar vía servicio si ya existe
            $svc = Get-Service -Name nginx* -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($svc) {
                $svcPath = (Get-WmiObject win32_service | Where-Object { $_.Name -eq $svc.Name }).PathName
                if ($svcPath -match '"?([^"]+)\\nginx.exe"?') {
                    $pathsToCheck.Insert(0, $matches[1])
                }
            }

            $path = ""
            foreach ($p in ($pathsToCheck | Select-Object -Unique)) {
                if (Test-Path "$p\conf\nginx.conf") { $path = $p; break }
                # A veces nginx.conf esta directamente en la carpeta o en un subnivel distinto
                if (Test-Path "$p\nginx.conf") { $path = $p; break }
            }

            if ([string]::IsNullOrEmpty($path)) {
                Write-LogError "No se pudo localizar la instalación de Nginx en: $($pathsToCheck -join ', '). Revisa el output de Chocolatey arriba."
                return
            }

            $conf = "$path\conf\nginx.conf"
            $c = Get-Content $conf -ErrorAction SilentlyContinue
            if ($null -eq $c) { Write-LogError "No se pudo leer el archivo de configuración en $conf."; return }

            $c = $c -replace 'listen\s+80;', "listen $Port;"
            $c = $c -replace 'server_tokens\s+\w+;', "server_tokens off;"
            $c | Set-Content $conf
            Set-ServicePermissions -ServiceName "nginx" -Path "$path\html"
            Generate-IndexHtml -Path "$path\html\index.html" -Svc "Nginx" -Ver $Version -Port $Port

            if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
                New-Service -Name "nginx" -BinaryPathName "$path\nginx.exe" -DisplayName "Nginx Server" -StartupType Automatic | Out-Null
            }
            Restart-Service nginx -ErrorAction SilentlyContinue
        }
        "apache" {
            Write-LogInfo "Ejecutando choco install apache-httpd..."
            choco install apache-httpd --version=$Version -y --no-progress
            
            # Intentar detectar la ruta de instalación
            $possiblePaths = New-Object System.Collections.Generic.List[string]
            $possiblePaths.Add("C:\tools\apache24")
            $possiblePaths.Add("C:\Apache24")
            $possiblePaths.Add("$env:SystemDrive\tools\apache24")
            if ($env:ChocolateyToolsLocation) { $possiblePaths.Add("$env:ChocolateyToolsLocation\apache24") }
            
            # Intentar detectar vía servicio si ya existe
            $svc = Get-Service -Name Apache* -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($svc) {
                $svcPath = (Get-WmiObject win32_service | Where-Object { $_.Name -eq $svc.Name }).PathName
                if ($svcPath -match '"?([^"]+)\\bin\\httpd.exe"?') {
                    $possiblePaths.Insert(0, $matches[1])
                }
            }

            $path = ""
            foreach ($p in $possiblePaths) {
                if (Test-Path "$p\conf\httpd.conf") { $path = $p; break }
            }

            if ([string]::IsNullOrEmpty($path)) {
                Write-LogError "No se pudo localizar la instalación de Apache en: $($possiblePaths -join ', '). Revisa el output de Chocolatey arriba."
                return
            }

            $conf = "$path\conf\httpd.conf"
            $c = Get-Content $conf -ErrorAction SilentlyContinue
            if ($null -eq $c) { Write-LogError "No se pudo leer el archivo de configuración en $conf."; return }
            
            $c = $c -replace 'Listen 80', "Listen $Port"
            $c = $c -replace 'ServerTokens \w+', "ServerTokens Prod"
            $c | Set-Content $conf
            Set-ServicePermissions -ServiceName "apache" -Path "$path\htdocs"
            Generate-IndexHtml -Path "$path\htdocs\index.html" -Svc "Apache" -Ver $Version -Port $Port
            Restart-Service Apache* -ErrorAction SilentlyContinue
        }
    }
    Set-HttpFirewallRule -Port $Port -Svc $Service
    Write-LogSuccess "$Service desplegado en puerto $Port."
}

# ==============================================================================
# MENU INTERFACE
# ==============================================================================

function Get-UserChoice {
    param([string]$Prompt)
    Write-Host "`n$Prompt" -ForegroundColor Cyan -NoNewline
    return (Read-Host).Trim()
}

function Request-ValidPort {
    while ($true) {
        $pStr = Get-UserChoice -Prompt "Ingrese puerto de escucha: "
        $p = 0
        if ([int]::TryParse($pStr, [ref]$p)) {
            if (-not (Test-PortInRange -Port $p)) { Write-LogWarn "Rango invalido."; continue }
            if ($p -lt 1024 -and $p -ne 80) { Write-LogWarn "Puerto reservado."; continue }
            if (Test-PortInUse -Port $p) {
                Write-LogWarn "Puerto ocupado. ¿Liberar proceso? (s/n): " -NoNewline
                if ((Read-Host).ToLower() -eq 's') {
                    $conn = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
                    if ($conn) { Stop-Process -Id $conn.OwningProcess -Force; Start-Sleep 1 }
                } else { continue }
            }
            return $p
        }
    }
}

function Show-VersionMenu {
    param([string]$Svc)
    $v = Get-DynamicVersions -Service $Svc
    Write-Host "`n--- Versiones para $Svc ---"
    for ($i=0; $i -lt $v.Count; $i++) { Write-Host "  $($i+1)) $($v[$i])" }
    $s = Get-UserChoice -Prompt "Seleccione [1-$($v.Count)]: "
    $idx = 0
    if ([int]::TryParse($s, [ref]$idx) -and $idx -ge 1 -and $idx -le $v.Count) { return $v[$idx-1] }
    return $v[0]
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if ($Help) {
    Write-Host "Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port <numero>] [-Status] [-Purge]"
    exit 0
}

if ($Status) {
    Write-Host "`n--- Estado de Servicios ---" -ForegroundColor White
    Get-Service -Name W3SVC, Apache*, nginx -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-Table -AutoSize
    exit 0
}

if ($Purge) {
    Write-LogWarn "Iniciando eliminación completa de servicios..."
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Stop-Service W3SVC, Apache*, nginx -Force -ErrorAction SilentlyContinue
    choco uninstall nginx apache-httpd -y -ErrorAction SilentlyContinue
    Remove-Item "C:\tools\nginx", "C:\tools\apache24", "C:\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    Write-LogSuccess "Eliminación completada."
    exit 0
}

if ($Service -ne "") {
    if ($Port -eq 0) { Write-LogError "El parámetro -Port es obligatorio para el modo no interactivo."; exit 1 }
    $Version = Get-DynamicVersions -Service $Service | Select-Object -First 1
    Install-WebServer -Service $Service -Port $Port -Version $Version
    exit 0
}

while ($true) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "   SISTEMA HTTP CONSOLIDADO (WINDOWS)     " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1) IIS`n2) Apache`n3) Nginx`n4) Estado`n5) Ayuda`nq) Salir"
    $c = Get-UserChoice -Prompt "Seleccione: "

    switch ($c) {
        "1" { Install-WebServer -Service "iis" -Port (Request-ValidPort) -Version (Get-DynamicVersions -Service "iis" | Select-Object -First 1) }
        "2" { Install-WebServer -Service "apache" -Port (Request-ValidPort) -Version (Show-VersionMenu -Service "apache") }
        "3" { Install-WebServer -Service "nginx" -Port (Request-ValidPort) -Version (Show-VersionMenu -Service "nginx") }
        "4" { Get-Service W3SVC, Apache*, nginx -ErrorAction SilentlyContinue | Select Name, Status | FT -Auto }
        "5" { 
            Write-Host "`n--- Ayuda de Uso ---" -ForegroundColor White
            Write-Host "Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port <numero>] [-Status] [-Purge]"
            Write-Host "Modo Interactivo: Ejecutar sin parámetros."
        }
        "q" { exit 0 }
    }
    Read-Host "`nEnter para continuar..."
}
