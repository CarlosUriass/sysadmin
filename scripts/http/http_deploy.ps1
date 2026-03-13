# Requires -RunAsAdministrator
#Requires -Version 5.1
# ==============================================================================
# Script: http_deploy.ps1
# Descripcion: Despliegue dinamico y hardening HTTP (Practica 6) - Windows
# Guardar con encoding: UTF-8 con BOM
# ==============================================================================

param(
    [string]$Service = "",
    [int]$Port = 0,
    [string]$ServiceVersion = "",
    [switch]$ListVersions,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ==============================================================================
# LOGGING
# ==============================================================================

function Write-LogInfo    ([string]$m) { Write-Host "[INFO] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Cyan   }
function Write-LogSuccess ([string]$m) { Write-Host "[OK]   $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Green  }
function Write-LogWarn    ([string]$m) { Write-Host "[WARN] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Yellow }
function Write-LogError   ([string]$m) { Write-Host "[FAIL] $(Get-Date -F 'HH:mm:ss') - $m" -ForegroundColor Red   }

# ==============================================================================
# UTILS
# ==============================================================================

function Test-PortInUse ([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Get-NearbyAvailablePorts ([int]$Port) {
    $s = @()
    for ($i = $Port + 1; $i -le [Math]::Min($Port + 20, 65535); $i++) {
        if (-not (Test-PortInUse $i)) { $s += $i; if ($s.Count -ge 3) { break } }
    }
    return $s
}

function Ensure-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-LogWarn "Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
        refreshenv 2>$null
    }
}

function Get-ChocoInstallPath ([string]$ExeName, [string[]]$Candidates) {
    foreach ($c in $Candidates) { if (Test-Path $c) { return $c } }
    $found = Get-Command $ExeName -ErrorAction SilentlyContinue
    if ($found) { return Split-Path $found.Source -Parent }
    return $null
}

function Generate-IndexHtml {
    param([string]$Path, [string]$Svc, [string]$Ver, [int]$Port)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $html = @"
<html><body>
<h1>Servidor: $Svc - Version: $Ver - Puerto: $Port</h1>
<p>Aprovisionamiento Automatizado - Windows (Practica 6)</p>
<p>Fecha: $time</p>
</body></html>
"@
    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))
    Write-LogSuccess "Pagina index.html generada en $Path"
}

# ==============================================================================
# SECURITY & HARDENING
# ==============================================================================

function Set-ServiceUserAndPermissions {
    param([string]$ServiceName, [string]$Path)
    $user = "svc_$ServiceName"
    Write-LogInfo "Configurando aislamiento de usuario para $ServiceName ($user)..."

    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        $pass = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force
        New-LocalUser -Name $user -Password $pass -Description "Service user for $ServiceName" | Out-Null
    }

    if (Test-Path $Path) {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $true)

        $rules = $acl.Access | Where-Object {
            $_.IdentityReference -match "BUILTIN\\Users$" -and $_.IsInherited -eq $false
        }
        foreach ($r in $rules) { $acl.RemoveAccessRule($r) | Out-Null }

        foreach ($identity in @($user, "IUSR", "IIS_IUSRS")) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, "ReadAndExecute",
                "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.SetAccessRule($rule)
        }

        Set-Acl $Path $acl
        Write-LogInfo "Permisos ACL aplicados en $Path"
    }
}

# ── FIX: Detener WAS + W3SVC para liberar el handle de applicationHost.config ──
# W3SVC depende de WAS; deteniendo WAS se liberan todos los handles de IIS
function Stop-IISServices {
    Write-LogInfo "Deteniendo WAS y W3SVC para liberar applicationHost.config..."
    Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
    Stop-Service WAS   -Force -ErrorAction SilentlyContinue
    # Esperar hasta que ambos esten detenidos (max 15s)
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        $w3  = (Get-Service W3SVC -ErrorAction SilentlyContinue).Status
        $was = (Get-Service WAS   -ErrorAction SilentlyContinue).Status
        if ($w3 -ne 'Running' -and $was -ne 'Running') { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 1   # margen extra para que el SO cierre los handles
}

function Start-IISServices {
    Write-LogInfo "Iniciando WAS y W3SVC..."
    Start-Service WAS   -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Service W3SVC -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

function Apply-IISHardening ([int]$Port) {
    Write-LogInfo "Aplicando Hardening a IIS..."
    Import-Module WebAdministration -ErrorAction Stop

    $configPath = "$env:SystemRoot\system32\inetsrv\config\applicationHost.config"

    Stop-IISServices

    # ── Modificar applicationHost.config via XML directo ──
    try {
        [xml]$config = Get-Content $configPath -Encoding UTF8

        # Cambiar binding del Default Web Site
        $site = $config.configuration.'system.applicationHost'.sites.site |
                Where-Object { $_.name -eq "Default Web Site" }

        if ($site) {
            $bindingsNode = $site.bindings
            $bindingsNode.RemoveAll()
            $newBinding = $config.CreateElement("binding")
            $newBinding.SetAttribute("protocol", "http")
            $newBinding.SetAttribute("bindingInformation", "*:${Port}:")
            $bindingsNode.AppendChild($newBinding) | Out-Null
            Write-LogInfo "Binding IIS configurado en puerto $Port"
        } else {
            Write-LogWarn "Sitio 'Default Web Site' no encontrado en applicationHost.config"
        }

        $config.Save($configPath)
        Write-LogInfo "applicationHost.config guardado correctamente."

    } catch {
        Write-LogWarn "No se pudo modificar applicationHost.config: $_"
        Write-LogInfo "El puerto se configurara via web.config como fallback."
    }

    Start-IISServices

    # ── web.config: headers de seguridad (siempre sobreescribir, nunca acumular) ──
    # Se sobreescribe completamente para evitar el error 500.19 de duplicate key
    $webConfig = "C:\inetpub\wwwroot\web.config"
    $webConfigContent = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <clear />
        <remove name="X-Powered-By" />
        <add name="X-Frame-Options" value="SAMEORIGIN" />
        <add name="X-Content-Type-Options" value="nosniff" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering removeServerHeader="true">
        <verbs allowUnlisted="true">
          <clear />
          <add verb="TRACE" allowed="false" />
          <add verb="TRACK" allowed="false" />
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
'@
    # Crear directorio si no existe (primer deploy)
    $webDir = Split-Path $webConfig -Parent
    if (-not (Test-Path $webDir)) { New-Item -ItemType Directory -Path $webDir -Force | Out-Null }

    [System.IO.File]::WriteAllText($webConfig, $webConfigContent, [System.Text.UTF8Encoding]::new($false))
    Write-LogInfo "web.config escrito (idempotente, sin duplicados)."
}

function Set-FirewallRule ([int]$Port, [string]$Svc) {
    $name = "HTTP-Allow-$Svc-$Port"
    Write-LogInfo "Configurando Firewall para puerto $Port ($Svc)..."
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP `
            -LocalPort $Port -Action Allow | Out-Null
    }
}

# ==============================================================================
# VERSION DISCOVERY
# ==============================================================================

function Get-DynamicVersions ([string]$Service) {
    Ensure-Chocolatey
    $versions = @()
    switch ($Service.ToLower()) {
        "iis"    { return @("10.0") }
        "apache" {
            try {
                $out = choco search apache-httpd --exact --all-versions 2>$null |
                       Select-String "apache-httpd\s+\d"
                foreach ($l in $out) { $versions += ($l.ToString().Trim() -split '\s+')[1] }
            } catch {}
            if ($versions.Count -eq 0) { $versions = @("2.4.58", "2.4.55", "2.4.54") }
        }
        "nginx" {
            try {
                $out = choco search nginx --exact --all-versions 2>$null |
                       Select-String "^nginx\s+\d"
                foreach ($l in $out) { $versions += ($l.ToString().Trim() -split '\s+')[1] }
            } catch {}
            if ($versions.Count -eq 0) { $versions = @("1.27.4", "1.26.3", "1.24.0") }
        }
    }
    return $versions | Select-Object -First 5
}

# ==============================================================================
# INSTALADORES
# ==============================================================================

function Install-IIS ([int]$Port, [string]$Version) {
    $features = @(
        "IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures",
        "IIS-DefaultDocument", "IIS-StaticContent", "IIS-RequestFiltering",
        "IIS-ManagementConsole"
    )
    foreach ($f in $features) {
        $state = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue).State
        if ($state -ne "Enabled") {
            Write-LogInfo "Habilitando feature: $f"
            Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null
        }
    }

    # Arranque inicial para que IIS cree su estructura de directorios
    Start-Service WAS   -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Service W3SVC -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4

    # Hardening: detiene IIS, modifica config, reinicia IIS
    Apply-IISHardening -Port $Port

    Generate-IndexHtml -Path "C:\inetpub\wwwroot\index.html" -Svc "IIS" -Ver $Version -Port $Port
    Set-ServiceUserAndPermissions -ServiceName "iis" -Path "C:\inetpub\wwwroot"
}

function Install-ApacheHTTP ([int]$Port, [string]$Version) {
    Ensure-Chocolatey

    Write-LogInfo "Instalando Apache $Version via Chocolatey..."
    choco install apache-httpd --version=$Version -y --no-progress 2>&1 | Out-Null

    $candidates = @(
        "C:\tools\apache24",
        "C:\Apache24",
        "C:\Program Files\Apache Software Foundation\Apache2.4",
        "$env:SystemDrive\tools\Apache24"
    )
    $chocoLib = "$env:ALLUSERSPROFILE\chocolatey\lib\apache-httpd"
    if (Test-Path $chocoLib) {
        $subdir = Get-ChildItem $chocoLib -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($subdir) { $candidates = @($subdir.FullName) + $candidates }
    }

    $apachePath = Get-ChocoInstallPath -ExeName "httpd.exe" -Candidates $candidates
    if (-not $apachePath) {
        Write-LogError "No se encontro la instalacion de Apache."
        return
    }
    Write-LogInfo "Apache encontrado en: $apachePath"

    $conf = "$apachePath\conf\httpd.conf"
    if (-not (Test-Path $conf)) { Write-LogError "httpd.conf no encontrado en $conf"; return }

    $c = Get-Content $conf -Raw
    $c = $c -replace '(?m)^Listen\s+80\b',           "Listen $Port"
    $c = $c -replace '(?m)^#?ServerTokens\s+\w+',    "ServerTokens Prod"
    $c = $c -replace '(?m)^#?ServerSignature\s+\w+', "ServerSignature Off"
    $c = $c -replace '#LoadModule headers_module',    'LoadModule headers_module'

    if ($c -notmatch "X-Frame-Options") {
        $c += "`r`nHeader always set X-Frame-Options SAMEORIGIN"
        $c += "`r`nHeader always set X-Content-Type-Options nosniff"
    }
    if ($c -notmatch "LimitExcept") {
        $c += "`r`n<Directory `"$($apachePath -replace '\\','/')/htdocs`">`r`n    <LimitExcept GET POST>`r`n        Deny from all`r`n    </LimitExcept>`r`n</Directory>"
    }

    [System.IO.File]::WriteAllText($conf, $c, [System.Text.UTF8Encoding]::new($false))

    Set-ServiceUserAndPermissions -ServiceName "apache" -Path "$apachePath\htdocs"
    Generate-IndexHtml -Path "$apachePath\htdocs\index.html" -Svc "Apache" -Ver $Version -Port $Port

    if (-not (Get-Service "Apache*" -ErrorAction SilentlyContinue)) {
        $httpd = "$apachePath\bin\httpd.exe"
        if (Test-Path $httpd) { & $httpd -k install 2>&1 | Out-Null; Write-LogInfo "Servicio Apache registrado." }
    }
    Restart-Service "Apache*" -Force -ErrorAction SilentlyContinue
}

function Install-NginxHTTP ([int]$Port, [string]$Version) {
    Ensure-Chocolatey

    Write-LogInfo "Instalando Nginx $Version via Chocolatey..."
    choco install nginx --version=$Version -y --no-progress 2>&1 | Out-Null

    $candidates = @(
        "C:\tools\nginx",
        "C:\nginx",
        "$env:SystemDrive\tools\nginx",
        "$env:ALLUSERSPROFILE\chocolatey\lib\nginx\tools\nginx"
    )
    $nginxPath = Get-ChocoInstallPath -ExeName "nginx.exe" -Candidates $candidates
    if (-not $nginxPath) { Write-LogError "No se encontro la instalacion de Nginx."; return }
    Write-LogInfo "Nginx encontrado en: $nginxPath"

    $conf = "$nginxPath\conf\nginx.conf"
    if (-not (Test-Path $conf)) { Write-LogError "nginx.conf no encontrado en $conf"; return }

    $c = Get-Content $conf -Raw
    $c = $c -replace 'listen\s+80;',              "listen $Port;"
    $c = $c -replace 'listen\s+\[::\]:80;',       "listen [::]:$Port;"
    $c = $c -replace '#?\s*server_tokens\s+\w+;', "server_tokens off;"

    if ($c -notmatch "X-Frame-Options") {
        $c = $c -replace '(server\s*\{)', "`$1`n        add_header X-Frame-Options SAMEORIGIN;`n        add_header X-Content-Type-Options nosniff;"
    }

    [System.IO.File]::WriteAllText($conf, $c, [System.Text.UTF8Encoding]::new($false))

    Set-ServiceUserAndPermissions -ServiceName "nginx" -Path "$nginxPath\html"
    Generate-IndexHtml -Path "$nginxPath\html\index.html" -Svc "Nginx" -Ver $Version -Port $Port

    if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
        $nginxExe = "$nginxPath\nginx.exe"
        if (Get-Command nssm -ErrorAction SilentlyContinue) {
            nssm install nginx $nginxExe | Out-Null
        } else {
            New-Service -Name "nginx" -BinaryPathName "`"$nginxExe`"" -StartupType Automatic | Out-Null
        }
        Write-LogInfo "Servicio nginx registrado."
    }
    Restart-Service nginx -Force -ErrorAction SilentlyContinue
}

# ==============================================================================
# INSTALADOR PRINCIPAL
# ==============================================================================

function Install-WebServer ([string]$Service, [int]$Port, [string]$Version) {
    Write-LogInfo "Iniciando despliegue de $Service ($Version) en puerto $Port..."

    if (Test-PortInUse -Port $Port) {
        $s = Get-NearbyAvailablePorts -Port $Port
        $msg = "Puerto $Port ocupado."
        if ($s.Count -gt 0) { $msg += " Recomendados: $($s -join ', ')" }
        Write-LogError $msg
        return
    }

    switch ($Service.ToLower()) {
        "iis"    { Install-IIS        -Port $Port -Version $Version }
        "apache" { Install-ApacheHTTP -Port $Port -Version $Version }
        "nginx"  { Install-NginxHTTP  -Port $Port -Version $Version }
        default  { Write-LogError "Servicio no soportado: $Service"; return }
    }

    Set-FirewallRule -Port $Port -Svc $Service
    Write-LogSuccess "Servicio $Service desplegado con exito en puerto $Port."
}

# ==============================================================================
# ESTADO / PURGA
# ==============================================================================

function Show-Status {
    Write-Host "`n--- ESTADO DE SERVICIOS (WINDOWS) ---" -ForegroundColor White
    Get-Service -Name W3SVC, WAS, Apache*, nginx -ErrorAction SilentlyContinue |
        Select-Object Name, Status | Format-Table -AutoSize
    Write-Host "`n--- PUERTOS HTTP ACTIVOS ---" -ForegroundColor White
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in (80, 443, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010) } |
        Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

function Invoke-Purge {
    Write-LogWarn "Iniciando purga total de servicios HTTP..."
    Stop-IISServices
    Stop-Service Apache*, nginx -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete nginx  2>$null | Out-Null
    sc.exe delete Apache 2>$null | Out-Null

    Ensure-Chocolatey
    choco uninstall nginx apache-httpd -y --remove-dependencies 2>&1 | Out-Null

    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" `
            -NoRestart -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    Get-NetFirewallRule -DisplayName "HTTP-Allow-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-LogSuccess "Purga completada."
}

# ==============================================================================
# MODO INTERACTIVO
# ==============================================================================

function Request-ValidPort {
    while ($true) {
        Write-Host "Ingrese puerto (80 o 1024-65535): " -ForegroundColor Cyan -NoNewline
        $pStr = Read-Host
        $p = 0
        if ([int]::TryParse($pStr, [ref]$p) -and ($p -eq 80 -or ($p -ge 1024 -and $p -le 65535))) {
            if (-not (Test-PortInUse -Port $p)) { return $p }
            $s = Get-NearbyAvailablePorts -Port $p
            Write-LogError "Puerto $p ocupado. Disponibles: $($s -join ', ')"
        } else {
            Write-LogWarn "Puerto invalido. Use 80 o un valor entre 1024 y 65535."
        }
    }
}

function Select-Version ([string]$Service) {
    $v = Get-DynamicVersions -Service $Service
    Write-Host "Seleccione version:" -ForegroundColor Cyan
    for ($i = 0; $i -lt [Math]::Min($v.Count, 5); $i++) { Write-Host "  $($i+1)) $($v[$i])" }
    Write-Host "  (Enter para la mas reciente)" -ForegroundColor Gray
    $sel = Read-Host "Opcion"
    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $v.Count) { return $v[$idx - 1] }
    return $v[0]
}

function Main {
    if ($Help) {
        Write-Host @"
Uso: .\http_deploy.ps1 [-Service iis|apache|nginx] [-Port <num>]
                       [-ServiceVersion <ver>] [-ListVersions] [-Status] [-Purge]
Ejemplos:
  .\http_deploy.ps1 -Service nginx  -Port 3001
  .\http_deploy.ps1 -Service apache -Port 3002 -ServiceVersion 2.4.55
  .\http_deploy.ps1 -ListVersions -Service nginx
  .\http_deploy.ps1 -Status
  .\http_deploy.ps1 -Purge
"@
        return
    }

    if ($Status) { Show-Status; return }
    if ($Purge)  { Invoke-Purge; return }

    if ($Service -ne "") {
        if ($ListVersions) {
            Write-LogInfo "Versiones disponibles para ${Service}:"
            Get-DynamicVersions -Service $Service | ForEach-Object { Write-Host "  - $_" }
            return
        }
        if ($Port -eq 0) { Write-LogError "Especifica el puerto con -Port <num>"; return }
        $ver = if ($ServiceVersion) { $ServiceVersion } else { (Get-DynamicVersions -Service $Service)[0] }
        Install-WebServer -Service $Service -Port $Port -Version $ver
        return
    }

    while ($true) {
        Write-Host "`n=== SISTEMA DE APROVISIONAMIENTO HTTP (Practica 6) ===" -ForegroundColor Cyan
        Write-Host "  1) IIS`n  2) Apache`n  3) Nginx`n  4) Estado`n  5) Purgar`n  q) Salir"
        $choice = Read-Host "Seleccione"
        switch ($choice.ToLower()) {
            "1" { $p = Request-ValidPort; Install-WebServer -Service "iis"    -Port $p -Version "10.0" }
            "2" { $ver = Select-Version "apache"; $p = Request-ValidPort; Install-WebServer -Service "apache" -Port $p -Version $ver }
            "3" { $ver = Select-Version "nginx";  $p = Request-ValidPort; Install-WebServer -Service "nginx"  -Port $p -Version $ver }
            "4" { Show-Status }
            "5" { Invoke-Purge }
            "q" { Write-Host "Saliendo..."; return }
            default { Write-LogWarn "Opcion no valida." }
        }
    }
}

Main