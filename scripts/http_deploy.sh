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

    # Mapeo de build de Windows → versión de IIS
    $ver = switch ($true) {
        ($build -ge 20348) { "10.0 (Windows Server 2022)" }
        ($build -ge 17763) { "10.0 (Windows Server 2019)" }
        ($build -ge 14393) { "10.0 (Windows Server 2016)" }
        ($build -ge 9600)  { "8.5 (Windows Server 2012 R2)" }
        default            { "10.0 (Windows Server detectado)" }
    }

    Write-Host ""
    Write-Host "Versiones disponibles de IIS:" -ForegroundColor White
    Write-Host "  1) IIS $ver" -NoNewline
    Write-Host "  (instalado con este SO)" -ForegroundColor Green
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
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Log-Error "No se pudo instalar Chocolatey. Requerido para Nginx en Windows."
        }
    }

    # Consultar versiones disponibles
    $chocoOut = choco search nginx --exact --all-versions 2>$null | Select-String "nginx\s+\d"
    $versions = @()
    foreach ($line in $chocoOut) {
        $parts = $line.ToString().Trim() -split '\s+'
        if ($parts.Count -ge 2) { $versions += $parts[1] }
    }

    # Fallback si choco no devuelve lista
    if ($versions.Count -eq 0) {
        Log-Warn "No se obtuvieron versiones via choco. Usando versiones conocidas."
        $versions = @("1.27.4", "1.26.3", "1.24.0")
    }

    $maxShow = [Math]::Min($versions.Count, 5)
    Write-Host ""
    Write-Host "Versiones disponibles de Nginx:" -ForegroundColor White
    for ($i = 0; $i -lt $maxShow; $i++) {
        $num = $i + 1
        Write-Host "  ${num}) $($versions[$i])  " -NoNewline
        if     ($i -eq 0)           { Write-Host "(Mainline/Latest)" -ForegroundColor Yellow }
        elseif ($i -eq ($maxShow-1)){ Write-Host "(Estable/LTS)"    -ForegroundColor Green  }
        else                        { Write-Host "" }
    }
    Write-Host ""

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $versions[0]
        return $true
    }

    while ($true) {
        Write-Host "Selecciona una version [1-$maxShow]: " -ForegroundColor Cyan -NoNewline
        $sel = Read-Host
        $idx = 0
        if ([int]::TryParse($sel.Trim(), [ref]$idx) -and $idx -ge 1 -and $idx -le $maxShow) {
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
        $url     = "https://dlcdn.apache.org/tomcat/tomcat-${rama}/"
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $matches = [regex]::Matches($content.Content, 'v(\d+\.\d+\.\d+)/')
        $versions = $matches | ForEach-Object { [version]$_.Groups[1].Value } | Sort-Object
        if ($versions.Count -gt 0) {
            return $versions[-1].ToString()
        }
    } catch {}
    return $null
}

function Get-TomcatVersions {
    Log-Info "Consultando versiones disponibles de Tomcat..."

    # Verificar Java
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        Log-Warn "Java no encontrado. Instalando OpenJDK 17 via winget..."
        winget install --id Microsoft.OpenJDK.17 --silent --accept-package-agreements `
              --accept-source-agreements 2>$null
        $env:Path += ";$env:ProgramFiles\Microsoft\jdk-17"
        if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
            Log-Error "No se pudo instalar Java. Tomcat requiere Java."
        }
    }
    $javaVer = java -version 2>&1 | Select-Object -First 1
    Log-Success "Java disponible: $javaVer"

    Log-Info "Consultando versiones desde dlcdn.apache.org..."
    $v9  = Get-LatestTomcat "9"
    $v10 = Get-LatestTomcat "10"
    $v11 = Get-LatestTomcat "11"

    if (-not $v9)  { Log-Warn "Fallback Tomcat 9";  $v9  = "9.0.98"  }
    if (-not $v10) { Log-Warn "Fallback Tomcat 10"; $v10 = "10.1.34" }
    if (-not $v11) { Log-Warn "Fallback Tomcat 11"; $v11 = "11.0.3"  }

    $script:TOMCAT_VERSIONES = @{ "1" = $v9; "2" = $v10; "3" = $v11 }
    $script:TOMCAT_RAMAS     = @{ "1" = "9"; "2" = "10"; "3" = "11" }

    Write-Host ""
    Write-Host "Versiones disponibles de Tomcat:" -ForegroundColor White
    Write-Host "  1) Tomcat $v9  " -NoNewline; Write-Host "(Rama 9  - LTS, Java 8+)"   -ForegroundColor Green
    Write-Host "  2) Tomcat $v10 " -NoNewline; Write-Host "(Rama 10 - Estable, Java 11+)" -ForegroundColor Yellow
    Write-Host "  3) Tomcat $v11 " -NoNewline; Write-Host "(Rama 11 - Latest, Java 17+)"  -ForegroundColor Yellow
    Write-Host ""

    if (-not $script:INTERACTIVO) {
        $script:VERSION_ELEGIDA = $v11
        $script:TOMCAT_RAMA     = "11"
        return $true
    }

    while ($true) {
        Write-Host "Selecciona una version [1-3]: " -ForegroundColor Cyan -NoNewline
        $sel = Read-Host
        $idx = 0
        if ([int]::TryParse($sel.Trim(), [ref]$idx) -and $idx -ge 1 -and $idx -le 3) {
            $key = $idx.ToString()
            $script:VERSION_ELEGIDA = $script:TOMCAT_VERSIONES[$key]
            $script:TOMCAT_RAMA     = $script:TOMCAT_RAMAS[$key]
            Log-Success "Version seleccionada: Tomcat $($script:VERSION_ELEGIDA)"
            return $true
        }
        Log-Warn "Seleccion invalida. Ingresa 1, 2 o 3."
    }
}

# ==============================================================================
# INSTALAR IIS
# ==============================================================================
function Install-IIS {
    Write-Host "`n======================================="-ForegroundColor White
    Write-Host "  Instalando IIS"                       -ForegroundColor White
    Write-Host "=======================================" -ForegroundColor White

    Get-IISVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    Log-Info "Habilitando IIS via Windows Features..."
    $features = @(
        "IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures",
        "IIS-DefaultDocument", "IIS-StaticContent", "IIS-HttpCompressionStatic",
        "IIS-RequestFiltering", "IIS-Security"
    )
    foreach ($f in $features) {
        Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }

    # Configurar puerto en el binding de Default Web Site
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $site = Get-WebSite -Name "Default Web Site" -ErrorAction SilentlyContinue
    if ($site) {
        $binding = Get-WebBinding -Name "Default Web Site" -Protocol "http" -ErrorAction SilentlyContinue
        if ($binding) {
            Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" `
                -PropertyName BindingInformation -Value "*:$($script:PUERTO_ELEGIDO):" -ErrorAction SilentlyContinue
        } else {
            New-WebBinding -Name "Default Web Site" -Protocol "http" `
                -Port $script:PUERTO_ELEGIDO -IPAddress "*" -ErrorAction SilentlyContinue
        }
    }

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO

    Start-Service W3SVC -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $webroot = "C:\inetpub\wwwroot"
    New-IndexHtml -ruta "$webroot\index.html" -servicio "IIS" `
                  -version $script:VERSION_ELEGIDA -puerto $script:PUERTO_ELEGIDO
    Test-Service -servicio "W3SVC" -puerto $script:PUERTO_ELEGIDO
}

# ==============================================================================
# INSTALAR NGINX
# ==============================================================================
function Install-Nginx {
    Write-Host "`n=======================================" -ForegroundColor White
    Write-Host "  Instalando Nginx"                       -ForegroundColor White
    Write-Host "======================================="   -ForegroundColor White

    Get-NginxVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    Log-Info "Instalando Nginx $($script:VERSION_ELEGIDA) via Chocolatey..."
    choco install nginx --version=$script:VERSION_ELEGIDA -y --no-progress 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Log-Error "Fallo la instalacion de Nginx."
    }

    # Configurar puerto en nginx.conf
    $nginxConf = "C:\tools\nginx\conf\nginx.conf"
    if (-not (Test-Path $nginxConf)) {
        $nginxConf = "$env:ChocolateyInstall\lib\nginx\tools\nginx\conf\nginx.conf"
    }
    if (Test-Path $nginxConf) {
        (Get-Content $nginxConf) -replace 'listen\s+\d+;', "listen $($script:PUERTO_ELEGIDO);" |
            Set-Content $nginxConf -Encoding UTF8
        Log-Success "Puerto $($script:PUERTO_ELEGIDO) configurado en nginx.conf"
    } else {
        Log-Warn "No se encontro nginx.conf para configurar el puerto."
    }

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO

    # Crear servicio Windows para nginx si no existe
    $nginxExe = "C:\tools\nginx\nginx.exe"
    if (-not (Get-Service -Name "nginx" -ErrorAction SilentlyContinue)) {
        if (Test-Path $nginxExe) {
            New-Service -Name "nginx" -BinaryPathName $nginxExe -DisplayName "Nginx Web Server" `
                        -StartupType Automatic | Out-Null
        }
    }
    Start-Service nginx -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $webroot = "C:\tools\nginx\html"
    if (Test-Path $webroot) {
        New-IndexHtml -ruta "$webroot\index.html" -servicio "Nginx" `
                      -version $script:VERSION_ELEGIDA -puerto $script:PUERTO_ELEGIDO
    }
    Test-Service -servicio "nginx" -puerto $script:PUERTO_ELEGIDO
}

# ==============================================================================
# INSTALAR TOMCAT
# ==============================================================================
function Install-Tomcat {
    Write-Host "`n=======================================" -ForegroundColor White
    Write-Host "  Instalando Tomcat"                      -ForegroundColor White
    Write-Host "======================================="   -ForegroundColor White

    Get-TomcatVersions | Out-Null
    if ($script:PUERTO_ELEGIDO -eq 0) { Request-Port }

    $tomcatVer  = $script:VERSION_ELEGIDA
    $tomcatRama = $script:TOMCAT_RAMA
    $tomcatDir  = "C:\tomcat"
    $tomcatUrl  = "https://dlcdn.apache.org/tomcat/tomcat-${tomcatRama}/v${tomcatVer}/bin/apache-tomcat-${tomcatVer}-windows-x64.zip"
    $tmpZip     = "$env:TEMP\tomcat-${tomcatVer}.zip"

    Log-Info "Descargando Tomcat $tomcatVer desde: $tomcatUrl"
    try {
        Invoke-WebRequest -Uri $tomcatUrl -OutFile $tmpZip -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    } catch {
        Log-Error "Fallo la descarga de Tomcat: $_"
    }

    if (-not (Test-Path $tmpZip) -or (Get-Item $tmpZip).Length -eq 0) {
        Log-Error "El archivo descargado esta vacio o no existe."
    }

    Log-Info "Extrayendo Tomcat en $tomcatDir..."
    if (Test-Path $tomcatDir) { Remove-Item $tomcatDir -Recurse -Force }
    Expand-Archive -Path $tmpZip -DestinationPath "$env:TEMP\tomcat_extract" -Force
    $extracted = Get-ChildItem "$env:TEMP\tomcat_extract" -Directory | Select-Object -First 1
    Move-Item $extracted.FullName $tomcatDir
    Remove-Item $tmpZip -Force
    Remove-Item "$env:TEMP\tomcat_extract" -Recurse -Force -ErrorAction SilentlyContinue

    Log-Info "Configurando puerto $($script:PUERTO_ELEGIDO) en server.xml..."
    $serverXml = "$tomcatDir\conf\server.xml"
    (Get-Content $serverXml) -replace 'port="8080"', "port=`"$($script:PUERTO_ELEGIDO)`"" |
        Set-Content $serverXml -Encoding UTF8

    # Configurar JAVA_HOME
    $javaHome = (Get-Command java).Source | Split-Path | Split-Path
    [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "Machine")
    [System.Environment]::SetEnvironmentVariable("CATALINA_HOME", $tomcatDir, "Machine")

    Set-FirewallRule -puerto $script:PUERTO_ELEGIDO

    # Instalar como servicio Windows usando el instalador de Tomcat
    $serviceExe = "$tomcatDir\bin\service.bat"
    if (Test-Path $serviceExe) {
        Log-Info "Registrando Tomcat como servicio Windows..."
        $env:CATALINA_HOME = $tomcatDir
        $env:JAVA_HOME      = $javaHome
        & "$tomcatDir\bin\service.bat" install Tomcat 2>&1 | Out-Null
        Start-Service Tomcat -ErrorAction SilentlyContinue
    } else {
        Log-Warn "service.bat no encontrado. Iniciando Tomcat directamente..."
        Start-Process -FilePath "$tomcatDir\bin\startup.bat" -WindowStyle Hidden
    }

    Log-Info "Esperando que Tomcat inicie (15s)..."
    Start-Sleep -Seconds 15

    New-IndexHtml -ruta "$tomcatDir\webapps\ROOT\index.html" -servicio "Tomcat" `
                  -version $tomcatVer -puerto $script:PUERTO_ELEGIDO
    Test-Service -servicio "Tomcat" -puerto $script:PUERTO_ELEGIDO
}

# ==============================================================================
# MOSTRAR ESTADO DE SERVICIOS
# ==============================================================================
function Show-ServiceStatus {
    Write-Host "`nEstado de servicios HTTP:" -ForegroundColor White
    Write-Host "──────────────────────────────────────────"
    foreach ($svc in @("W3SVC", "nginx", "Tomcat")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            $port = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { $_.OwningProcess -in (Get-Process | Where-Object {
                         $_.Name -like "*$svc*" -or $_.Name -eq "java"
                     }).Id } | Select-Object -First 1).LocalPort
            Write-Host "  $svc`: " -NoNewline
            Write-Host "$($s.Status) " -ForegroundColor Cyan -NoNewline
            Write-Host "(puerto: $( if ($port) { $port } else { 'desconocido' } ))"
        } else {
            Write-Host "  $svc`: " -NoNewline
            Write-Host "no instalado" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# ==============================================================================
# PURGAR SERVICIOS
# ==============================================================================
function Remove-AllServices {
    Log-Info "Iniciando proceso de purgado total de servicios HTTP..."
    Write-Host "`nADVERTENCIA: Esto eliminara IIS, Nginx y Tomcat, junto con sus configuraciones." `
        -ForegroundColor Red

    if ($script:INTERACTIVO) {
        $confirm = Read-Host "¿Estas seguro de que deseas continuar? [s/N]"
        if ($confirm -notmatch '^[sS]$') {
            Log-Info "Purgado cancelado por el usuario."
            return
        }
    }

    Log-Info "Eliminando IIS..."
    $iisFeatures = @(
        "IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures",
        "IIS-DefaultDocument","IIS-StaticContent","IIS-HttpCompressionStatic",
        "IIS-RequestFiltering","IIS-Security"
    )
    foreach ($f in $iisFeatures) {
        Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue | Out-Null
    }

    Log-Info "Eliminando Nginx..."
    Stop-Service nginx -Force -ErrorAction SilentlyContinue
    sc.exe delete nginx | Out-Null
    choco uninstall nginx -y --no-progress 2>&1 | Out-Null
    Remove-Item "C:\tools\nginx" -Recurse -Force -ErrorAction SilentlyContinue

    Log-Info "Eliminando Tomcat..."
    Stop-Service Tomcat -Force -ErrorAction SilentlyContinue
    if (Test-Path "C:\tomcat\bin\service.bat") {
        & "C:\tomcat\bin\service.bat" remove Tomcat 2>&1 | Out-Null
    }
    sc.exe delete Tomcat | Out-Null
    Remove-Item "C:\tomcat" -Recurse -Force -ErrorAction SilentlyContinue

    Log-Success "Purgado completado. Todos los servicios HTTP han sido eliminados."
}

# ==============================================================================
# AYUDA
# ==============================================================================
function Show-Help {
    Write-Host "Uso: .\http_deploy.ps1 [opciones]"
    Write-Host ""
    Write-Host "Opciones:"
    Write-Host "  -Help                  Muestra este mensaje de ayuda"
    Write-Host "  -Status                Muestra el estado de los servicios HTTP"
    Write-Host "  -Purge                 Elimina todas las configuraciones y servicios HTTP"
    Write-Host "  -Service <servicio>    Servicio a instalar: iis, nginx, tomcat"
    Write-Host "  -Port <puerto>         Puerto personalizado para la instalacion"
    Write-Host ""
    Write-Host "Ejemplo: .\http_deploy.ps1 -Service nginx -Port 8080"
}

# ==============================================================================
# MENÚ PRINCIPAL
# ==============================================================================
function Show-Menu {
    Clear-Host
    Write-Host "  Practica 6 - Despliegue HTTP Multi-Version" -ForegroundColor Cyan
    Write-Host "  1) Instalar IIS"
    Write-Host "  2) Instalar Nginx"
    Write-Host "  3) Instalar Tomcat"
    Write-Host "  4) Verificar servicios instalados"
    Write-Host "  5) Purgar todo (Eliminar servicios)"
    Write-Host "  0) Salir"
    Write-Host "  Selecciona una opcion: " -ForegroundColor Cyan -NoNewline
}

# ==============================================================================
# PUNTO DE ENTRADA
# ==============================================================================
if ($Help) { Show-Help; exit 0 }

Test-Connectivity

# ── Flujo No Interactivo ──────────────────────────────────────────────────────
if ($Status) { Show-ServiceStatus; exit 0 }

if ($Purge) {
    $script:INTERACTIVO = $false
    Remove-AllServices
    exit 0
}

if ($Service -ne "") {
    $script:INTERACTIVO = $false
    if ($Port -eq 0) {
        Log-Error "Debes especificar un puerto con -Port en modo no interactivo."
    }
    if (-not (Test-Port -puerto $Port)) { exit 1 }
    $script:PUERTO_ELEGIDO = $Port

    switch ($Service.ToLower()) {
        "iis"    { Install-IIS    }
        "nginx"  { Install-Nginx  }
        "tomcat" { Install-Tomcat }
        default  { Log-Error "Servicio '$Service' no soportado. Usa: iis, nginx, tomcat." }
    }
    exit 0
}

# ── Flujo Interactivo ─────────────────────────────────────────────────────────
while ($true) {
    Show-Menu
    $opcion = Read-Host
    $opcion = $opcion.Trim() -replace '[^0-9]', ''

    switch ($opcion) {
        "1" { $script:PUERTO_ELEGIDO = 0; Install-IIS    }
        "2" { $script:PUERTO_ELEGIDO = 0; Install-Nginx  }
        "3" { $script:PUERTO_ELEGIDO = 0; Install-Tomcat }
        "4" { Show-ServiceStatus }
        "5" { Remove-AllServices }
        "0" { Log-Success "Saliendo..."; exit 0 }
        default { Log-Warn "Opcion invalida. Ingresa 0, 1, 2, 3, 4 o 5."; Start-Sleep -Seconds 1 }
    }

    Write-Host "`nPresiona ENTER para volver al menu..." -ForegroundColor Cyan
    Read-Host | Out-Null
}
