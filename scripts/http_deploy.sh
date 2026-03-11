# ==============================================================================
# Práctica 6 - Despliegue Dinámico de Servicios HTTP Multi-Versión
# Sistema Operativo: Windows Server
# Uso interactivo: .\http_deploy.ps1
# Uso con parámetros: .\http_deploy.ps1 -Service iis -Port 8080
# Requiere: PowerShell 5.1+ y ejecutar como Administrador
# ==============================================================================

#Requires -RunAsAdministrator

param(
    [string]$Service   = "",
    [int]   $Port      = 0,
    [switch]$Status,
    [switch]$Purge,
    [switch]$Help
)

# ==============================================================================
# VARIABLES GLOBALES
# ==============================================================================
$script:VERSION_ELEGIDA = ""
$script:PUERTO_ELEGIDO  = $Port
$script:INTERACTIVO     = ($Service -eq "" -and -not $Status -and -not $Purge -and -not $Help)

# ==============================================================================
# LOGGER
# ==============================================================================
function Log-Info    { param([string]$msg) Write-Host "[INFO]    $msg" -ForegroundColor Cyan    }
function Log-Success { param([string]$msg) Write-Host "[OK]      $msg" -ForegroundColor Green   }
function Log-Warn    { param([string]$msg) Write-Host "[WARN]    $msg" -ForegroundColor Yellow  }
function Log-Error   {
    param([string]$msg)
    Write-Host "[ERROR]   $msg" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# VERIFICAR CONECTIVIDAD
# ==============================================================================
function Test-Connectivity {
    Log-Info "Verificando conectividad a internet..."
    $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $ping) {
        Log-Error "Sin conexión a internet. El script requiere acceso a repositorios."
    }
    Log-Success "Conectividad OK."
}

# ==============================================================================
# VALIDAR PUERTO
# ==============================================================================
function Test-Port {
    param([int]$puerto)

    if ($puerto -lt 1024 -or $puerto -gt 65535) {
        Log-Warn "Puerto $puerto inválido. Debe estar entre 1024 y 65535."
        return $false
    }

    $inUse = Get-NetTCPConnection -LocalPort $puerto -ErrorAction SilentlyContinue
    if ($inUse) {
        $pid = ($inUse | Select-Object -First 1).OwningProcess
        $proc = (Get-Process -Id $pid -ErrorAction SilentlyContinue).Name
        Log-Warn "Puerto $puerto en uso por: $proc (PID $pid). Intentando liberar..."
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $stillInUse = Get-NetTCPConnection -LocalPort $puerto -ErrorAction SilentlyContinue
        if ($stillInUse) {
            Log-Error "No se pudo liberar el puerto $puerto. Abortando."
            return $false
        }
        Log-Success "Puerto $puerto liberado exitosamente."
    }
    return $true
}

# ==============================================================================
# PEDIR PUERTO AL USUARIO
# ==============================================================================
function Request-Port {
    while ($true) {
        Write-Host "Ingresa el puerto de escucha (ej: 8080, 8888): " -ForegroundColor Cyan -NoNewline
        $input = Read-Host
        $parsed = 0
        if ([int]::TryParse($input.Trim(), [ref]$parsed)) {
            if (Test-Port -puerto $parsed) {
                $script:PUERTO_ELEGIDO = $parsed
                Log-Success "Puerto $parsed aceptado."
                return
            }
        } else {
            Log-Warn "Entrada inválida. Ingresa solo números."
        }
    }
}

# ==============================================================================
# CONFIGURAR FIREWALL
# ==============================================================================
function Set-FirewallRule {
    param([int]$puerto)
    $ruleName = "HTTP-Custom-$puerto"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
            -LocalPort $puerto -Action Allow -Profile Any | Out-Null
        Log-Success "Regla de firewall agregada para puerto $puerto/TCP."
    } else {
        Log-Info "Regla de firewall para puerto $puerto ya existe."
    }
}

# ==============================================================================
# CREAR INDEX HTML
# ==============================================================================
function New-IndexHtml {
    param(
        [string]$ruta,
        [string]$servicio,
        [string]$version,
        [int]   $puerto
    )
    $fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$servicio - Practica 6</title>
</head>
<body>
    <h1>Practica 6 - $servicio</h1>
    <p>Version: $version</p>
    <p>Puerto: $puerto</p>
    <p>Desplegado: $fecha</p>
</body>
</html>
"@
    $html | Set-Content -Path $ruta -Encoding UTF8
    Log-Success "index.html creado en $ruta"
}

# ==============================================================================
# VERIFICAR SERVICIO
# ==============================================================================
function Test-Service {
    param([string]$servicio, [int]$puerto)

    Log-Info "Verificando servicio $servicio en puerto $puerto..."

    $svc = Get-Service -Name $servicio -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Log-Success "Servicio $servicio esta ACTIVO."
    } else {
        Log-Warn "El servicio $servicio no parece estar corriendo."
    }

    $conn = Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        Log-Success "Puerto $puerto esta escuchando."
    } else {
        Log-Warn "Puerto $puerto no detectado aun. Puede tardar unos segundos."
    }

    Log-Info "Probando respuesta HTTP..."
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$puerto" -UseBasicParsing `
                    -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            Log-Success "Servidor responde HTTP 200 en puerto $puerto OK"
        } else {
            Log-Warn "Respuesta HTTP: $($resp.StatusCode)"
        }
    } catch {
        Log-Warn "Sin respuesta HTTP aun (puede estar iniciando)."
    }
}

# ==============================================================================
# OBTENER VERSIONES: IIS
# ==============================================================================
function Get-IISVersions {
    Log-Info "Consultando versión de IIS disponible en este sistema..."

    $winVer = [System.Environment]::OSVersion.Version
    $build  = $winVer.Build

    $ver = switch ($true) {
        ($build -ge 20348) { "10.0 (Windows Server 2022)" }
        ($build -ge 17763) { "10.0 (Windows Server 2019)" }
        ($build -ge 14393) { "10.0 (Windows Server 2016)" }
        ($build -ge 9600)  { "8.5 (Windows Server 2012 R2)" }
        default            { "10.0 (Windows Server detectado)" }
    }

    Write-Host ""
    Write-Host "Versiones disponibles de IIS:" -ForegroundColor White
    Write-Host "  1) IIS $ver " -NoNewline
    Write-Host "(instalado con este SO)" -ForegroundColor Green
    Write-Host ""

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $ver
        return $true
    }

    while ($true) {
        Write-Host "Selecciona una version [1]: " -ForegroundColor Cyan -NoNewline
        $sel = Read-Host
        if ($sel.Trim() -eq "1" -or $sel.Trim() -eq "") {
            $script:VERSION_ELEGIDA = $ver
            Log-Success "Version seleccionada: IIS $ver"
            return $true
        }
        Log-Warn "Seleccion invalida. Ingresa 1."
    }
}

# ==============================================================================
# OBTENER VERSIONES: NGINX
# ==============================================================================
function Get-NginxVersions {
    Log-Info "Consultando versiones disponibles de Nginx (via Chocolatey)..."

    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Log-Warn "Chocolatey no encontrado. Instalando..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }

    $chocoOut = choco search nginx --exact --all-versions 2>$null | Select-String "nginx\s+\d"
    $versions = @()
    foreach ($line in $chocoOut) {
        $parts = $line.ToString().Trim() -split '\s+'
        if ($parts.Count -ge 2) { $versions += $parts[1] }
    }

    if ($versions.Count -eq 0) {
        Log-Warn "No se obtuvieron versiones via choco. Usando versiones conocidas."
        $versions = @("1.27.4", "1.26.3", "1.24.0")
    }

    $maxShow = [Math]::Min($versions.Count, 5)
    Write-Host ""
    Write-Host "Versiones disponibles de Nginx:" -ForegroundColor White
    for ($i = 0; $i -lt $maxShow; $i++) {
        $vNum = $i + 1
        $vStr = $versions[$i]
        Write-Host "  $vNum) $vStr  " -NoNewline
        if ($i -eq 0) { Write-Host "(Mainline/Latest)" -ForegroundColor Yellow }
        elseif ($i -eq ($maxShow - 1)) { Write-Host "(Estable/LTS)" -ForegroundColor Green }
        else { Write-Host "" }
    }
    Write-Host ""

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $versions[0]
        return $true
    }

    while ($true) {
        Write-Host "Selecciona una version [1-$maxShow]: " -ForegroundColor Cyan -NoNewline
        $sel = (Read-Host).Trim()
        $idx = 0
        if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $maxShow) {
            $script:VERSION_ELEGIDA = $versions[$idx - 1]
            Log-Success "Version seleccionada: $($script:VERSION_ELEGIDA)"
            return $true
        }
        Log-Warn "Seleccion invalida. Ingresa un numero entre 1 y $maxShow."
    }
}

# ==============================================================================
# OBTENER VERSIONES: TOMCAT
# ==============================================================================
function Get-LatestTomcat {
    param([string]$rama)
    try {
        $url = "https://dlcdn.apache.org/tomcat/tomcat-${rama}/"
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $matches = [regex]::Matches($content.Content, 'v(\d+\.\d+\.\d+)/')
        $versions = $matches | ForEach-Object { [version]$_.Groups[1].Value } | Sort-Object
        if ($versions.Count -gt 0) { return $versions[-1].ToString() }
    } catch {}
    return $null
}

function Get-TomcatVersions {
    Log-Info "Consultando versiones disponibles de Tomcat..."

    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Log-Warn "Java no encontrado. Instalando OpenJDK 17 via winget..."
        winget install --id Microsoft.OpenJDK.17 --silent --accept-package-agreements --accept-source-agreements 2>$null
        $env:Path += ";$env:ProgramFiles\Microsoft\jdk-17"
    }

    Log-Info "Consultando versiones desde dlcdn.apache.org..."
    $v9 = Get-LatestTomcat "9"; if (-not $v9) { $v9 = "9.0.98" }
    $v10 = Get-LatestTomcat "10"; if (-not $v10) { $v10 = "10.1.34" }
    $v11 = Get-LatestTomcat "11"; if (-not $v11) { $v11 = "11.0.3" }

    $script:TOMCAT_VERSIONES = @{ "1" = $v9; "2" = $v10; "3" = $v11 }
    $script:TOMCAT_RAMAS     = @{ "1" = "9"; "2" = "10"; "3" = "11" }

    Write-Host ""
    Write-Host "Versiones disponibles de Tomcat:" -ForegroundColor White
    Write-Host "  1) Tomcat $v9  " -NoNewline; Write-Host "(Rama 9 - LTS)" -ForegroundColor Green
    Write-Host "  2) Tomcat $v10 " -NoNewline; Write-Host "(Rama 10 - Estable)" -ForegroundColor Yellow
    Write-Host "  3) Tomcat $v11 " -NoNewline; Write-Host "(Rama 11 - Latest)" -ForegroundColor Yellow
    Write-Host ""

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $v11
        $script:TOMCAT_RAMA = "11"
        return $true
    }

    while ($true) {
        Write-Host "Selecciona una version [1-3]: " -ForegroundColor Cyan -NoNewline
        $sel = (Read-Host).Trim()
        if ($script:TOMCAT_VERSIONES.ContainsKey($sel)) {
            $script:VERSION_ELEGIDA = $script:TOMCAT_VERSIONES[$sel]
            $script:TOMCAT_RAMA = $script:TOMCAT_RAMAS[$sel]
            Log-Success "Version seleccionada: Tomcat $($script:VERSION_ELEGIDA)"
            return $true
        }
        Log-Warn "Seleccion invalida. Ingresa 1, 2 o 3."
    }
}

# ==============================================================================
# INSTALADORES (IIS, NGINX, TOMCAT)
# ==============================================================================
function Install-IIS {
    Write-Host "`n=== Instalando IIS ===" -ForegroundColor White
    Get-IISVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    Log-Info "Habilitando IIS..."
    $features = @("IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-DefaultDocument", "IIS-StaticContent")
    foreach ($f in $features) {
        Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName BindingInformation -Value "*:$($script:PUERTO_ELEGIDO):" -ErrorAction SilentlyContinue

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO
    Start-Service W3SVC -ErrorAction SilentlyContinue
    New-IndexHtml -ruta "C:\inetpub\wwwroot\index.html" -servicio "IIS" -version $script:VERSION_ELEGIDA -puerto $script:PUERTO_ELEGIDO
    Test-Service -servicio "W3SVC" -puerto $script:PUERTO_ELEGIDO
}

function Install-Nginx {
    Write-Host "`n=== Instalando Nginx ===" -ForegroundColor White
    Get-NginxVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    Log-Info "Instalando Nginx $($script:VERSION_ELEGIDA)..."
    choco install nginx --version=$script:VERSION_ELEGIDA -y --no-progress | Out-Null

    $nginxConf = "C:\tools\nginx\conf\nginx.conf"
    if (Test-Path $nginxConf) {
        (Get-Content $nginxConf) -replace 'listen\s+80;', "listen $($script:PUERTO_ELEGIDO);" | Set-Content $nginxConf
    }

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO
    $nginxExe = "C:\tools\nginx\nginx.exe"
    if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
        New-Service -Name "nginx" -BinaryPathName $nginxExe -DisplayName "Nginx" -StartupType Automatic | Out-Null
    }
    Start-Service nginx -ErrorAction SilentlyContinue
    New-IndexHtml -ruta "C:\tools\nginx\html\index.html" -servicio "Nginx" -version $script:VERSION_ELEGIDA -puerto $script:PUERTO_ELEGIDO
    Test-Service -servicio "nginx" -puerto $script:PUERTO_ELEGIDO
}

function Install-Tomcat {
    Write-Host "`n=== Instalando Tomcat ===" -ForegroundColor White
    Get-TomcatVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    $tomcatVer = $script:VERSION_ELEGIDA
    $tomcatDir = "C:\tomcat"
    $tomcatUrl = "https://dlcdn.apache.org/tomcat/tomcat-$($script:TOMCAT_RAMA)/v$tomcatVer/bin/apache-tomcat-$tomcatVer-windows-x64.zip"
    $tmpZip = "$env:TEMP\tomcat.zip"

    Log-Info "Descargando Tomcat..."
    Invoke-WebRequest -Uri $tomcatUrl -OutFile $tmpZip -UseBasicParsing

    if (Test-Path $tomcatDir) { Remove-Item $tomcatDir -Recurse -Force }
    Expand-Archive -Path $tmpZip -DestinationPath "$env:TEMP\tc_extract" -Force
    Move-Item (Get-ChildItem "$env:TEMP\tc_extract" -Directory).FullName $tomcatDir

    $serverXml = "$tomcatDir\conf\server.xml"
    (Get-Content $serverXml) -replace 'port="8080"', "port=`"$($script:PUERTO_ELEGIDO)`"" | Set-Content $serverXml

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO
    & "$tomcatDir\bin\service.bat" install Tomcat | Out-Null
    Start-Service Tomcat -ErrorAction SilentlyContinue
    New-IndexHtml -ruta "$tomcatDir\webapps\ROOT\index.html" -servicio "Tomcat" -version $tomcatVer -puerto $script:PUERTO_ELEGIDO
    Test-Service -servicio "Tomcat" -puerto $script:PUERTO_ELEGIDO
}

# ==============================================================================
# OTROS (STATUS, PURGE, HELP)
# ==============================================================================
function Show-ServiceStatus {
    Write-Host "`nEstado de servicios HTTP:" -ForegroundColor White
    foreach ($svc in @("W3SVC", "nginx", "Tomcat")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        $status = if ($s) { $s.Status } else { "No instalado" }
        Write-Host "  $svc: " -NoNewline; Write-Host $status -ForegroundColor Cyan
    }
}

function Remove-AllServices {
    Log-Warn "Iniciando purgado total..."
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Stop-Service nginx, Tomcat -Force -ErrorAction SilentlyContinue
    choco uninstall nginx -y 2>$null; Remove-Item "C:\tools\nginx", "C:\tomcat" -Recurse -Force -ErrorAction SilentlyContinue
    Log-Success "Purgado completado."
}

function Show-Help {
    Write-Host "Uso: .\http_deploy.ps1 [-Service iis|nginx|tomcat] [-Port 1024-65535] [-Status] [-Purge]"
}

function Show-Menu {
    Write-Host "`n--- Practica 6 - Menú Principal ---" -ForegroundColor Cyan
    Write-Host "1) Instalar IIS`n2) Instalar Nginx`n3) Instalar Tomcat`n4) Estado`n5) Purgar`n0) Salir"
    Write-Host "Seleccion: " -NoNewline
}

# ==============================================================================
# PUNTO DE ENTRADA
# ==============================================================================
if ($Help) { Show-Help; exit 0 }
Test-Connectivity

if ($Status) { Show-ServiceStatus; exit 0 }
if ($Purge)  { Remove-AllServices; exit 0 }

if ($Service -ne "") {
    if ($Port -eq 0) { Log-Error "Requiere -Port para modo no interactivo." }
    $script:PUERTO_ELEGIDO = $Port
    switch ($Service.ToLower()) {
        "iis"    { Install-IIS }
        "nginx"  { Install-Nginx }
        "tomcat" { Install-Tomcat }
    }
    exit 0
}

while ($true) {
    Show-Menu
    $op = (Read-Host).Trim()
    switch ($op) {
        "1" { Install-IIS }
        "2" { Install-Nginx }
        "3" { Install-Tomcat }
        "4" { Show-ServiceStatus }
        "5" { Remove-AllServices }
        "0" { exit 0 }
    }
}
