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
<html>
<head><title>Aprovisionamiento HTTP - Windows</title></head>
<body>
    <h1>Servidor: $Svc</h1>
    <p>Version: $Ver</p>
    <p>Puerto: $Port</p>
    <p>Fecha: $Time</p>
</body>
</html>
"@ | Set-Content -Path $Path -Encoding UTF8
}

function Install-WebServer {
    [OutputType([bool])]
    param([string]$Service, [int]$Port, [string]$Version)
    Write-LogInfo "Iniciando instalacion de $Service ($Version) en puerto $Port..."
    
    # Limpiar puerto si esta ocupado (matar procesos bloqueantes)
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($conn) {
        Write-LogWarn "El puerto $Port esta ocupado por PID: $($conn.OwningProcess -join ', '). Liberando..."
        foreach ($c in $conn) {
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 2
    }
    
    if ($Port -lt 1024 -and $Port -ne 80) {
        Write-LogWarn "Aviso: El puerto $Port es un puerto privilegiado (<1024). Podria requerir permisos especiales o estar bloqueado por el sistema."
    }
    
    switch ($Service.ToLower()) {
        "iis" {
            $features = @("IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-DefaultDocument", "IIS-StaticContent", "IIS-RequestFiltering")
            foreach ($f in $features) { Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null }
            Import-Module WebAdministration
            Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName BindingInformation -Value "*:$($Port):" -ErrorAction SilentlyContinue | Out-Null
            Apply-IISHardening
            Set-ServicePermissions -ServiceName "iis" -Path "C:\inetpub\wwwroot"
            Generate-IndexHtml -Path "C:\inetpub\wwwroot\index.html" -Svc "IIS" -Ver $Version -Port $Port
            Start-Service W3SVC -ErrorAction SilentlyContinue | Out-Null
            return [bool](Test-PortInUse -Port $Port)
        }
        "nginx" {
            Write-LogInfo "Ejecutando choco install nginx..."
            choco install nginx --version=$Version -y --no-progress | Out-Host
            
            $path = ""
            for ($i=0; $i -lt 2; $i++) {
                $pathsToCheck = @("C:\tools\nginx", "$env:SystemDrive\tools\nginx", "$env:AppData\nginx", "$env:LOCALAPPDATA\nginx")
                $pathsToCheck += @(Get-Item "C:\tools\nginx*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
                if ($env:ChocolateyToolsLocation) { $pathsToCheck += "$env:ChocolateyToolsLocation\nginx" }
                if ($env:ChocolateyInstall) { $pathsToCheck += "$env:ChocolateyInstall\lib\nginx\tools\nginx" }
                
                $cmd = Get-Command nginx.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($cmd) { $pathsToCheck += Split-Path -Path $cmd.Definition -Parent }

                $uniquePaths = $pathsToCheck | Where-Object { $_ } | Select-Object -Unique
                foreach ($p in $uniquePaths) {
                    if (Test-Path "$p\conf\nginx.conf") { $path = $p; break }
                    if (Test-Path "$p\nginx.conf") { $path = $p; break }
                }
                
                if ([string]::IsNullOrEmpty($path) -and $i -eq 0) {
                    Write-LogWarn "Nginx no encontrado en rutas conocidas. Reintentando con --force..."
                    choco install nginx --version=$Version -y --no-progress --force | Out-Host
                } else { break }
            }

            if ([string]::IsNullOrEmpty($path)) {
                Write-LogError "No se pudo localizar la instalación de Nginx en: $(($pathsToCheck | Select-Object -Unique) -join ', '). Revisa el output de Chocolatey arriba."
                return $false
            }

            $conf = "$path\conf\nginx.conf"
            $c = Get-Content $conf -ErrorAction SilentlyContinue
            if ($null -eq $c) { Write-LogError "No se pudo leer el archivo de configuración en $conf."; return $false }

            $c = $c -replace '(?mi)^\s*listen\s+.*?;', "    listen $Port;"
            $c = $c -replace '(?mi)^\s*server_tokens\s+.*?;', "    server_tokens off;"
            $c | Set-Content $conf
            Set-ServicePermissions -ServiceName "nginx" -Path "$path\html"
            Generate-IndexHtml -Path "$path\html\index.html" -Svc "Nginx" -Ver $Version -Port $Port

            if (-not (Get-Service nginx -ErrorAction SilentlyContinue)) {
                # Importante: nginx.exe no es un servicio nativo, suele requerir un wrapper.
                # Intentamos crearlo, pero advertimos si falla al arrancar.
                New-Service -Name "nginx" -BinaryPathName "$path\nginx.exe" -DisplayName "Nginx Server" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
            }
            
            Write-LogInfo "Reiniciando servicio Nginx desde $path..."
            Restart-Service nginx -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3

            $status = Get-Service nginx -ErrorAction SilentlyContinue
            if ($null -eq $status -or $status.Status -ne "Running") {
                Write-LogWarn "El servicio Nginx no está en ejecución o no existe. Intentando arranque directo..."
                # Matar procesos huérfanos antes de reintentar
                Stop-Process -Name nginx -Force -ErrorAction SilentlyContinue 
                Start-Process -FilePath "$path\nginx.exe" -WorkingDirectory $path -WindowStyle Hidden -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            $res = [bool](Test-PortInUse -Port $Port)
            if ($res) {
                Write-LogSuccess "Nginx verificado y escuchando en el puerto $Port."
            } else {
                Write-Host "Diagnostic: Checking port $($Port)..." -ForegroundColor Gray
                netstat -ano | Select-String ":$($Port)\s+" | Out-Host
                
                Write-Host "Comprobando logs en $path\logs..." -ForegroundColor Gray
                if (Test-Path "$path\logs\error.log") {
                    Get-Content "$path\logs\error.log" -Tail 10 | Out-Host
                } else {
                    Write-LogWarn "No se encontró log en $path\logs\error.log. Listando carpeta..."
                    Get-ChildItem "$path" -Recurse -Filter "*.log" -ErrorAction SilentlyContinue | Select -First 5 | FT -Auto | Out-Host
                }
            }
            return $res
        }
        "apache" {
            Write-LogInfo "Ejecutando choco install apache-httpd..."
            choco install apache-httpd --version=$Version -y --no-progress | Out-Host
            
            $path = ""
            for ($i=0; $i -lt 2; $i++) {
                $possiblePaths = @("C:\tools\apache24", "C:\Apache24", "$env:SystemDrive\tools\apache24", "$env:AppData\Apache24", "$env:LOCALAPPDATA\Apache24")
                $possiblePaths += @(Get-Item "C:\tools\apache*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
                if ($env:ChocolateyToolsLocation) { $possiblePaths += "$env:ChocolateyToolsLocation\apache24" }
                
                $svc = Get-Service -Name Apache* -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($svc) {
                    $svcPath = (Get-WmiObject win32_service | Where-Object { $_.Name -eq $svc.Name }).PathName
                    if ($svcPath -match '"?([^"]+)\\bin\\httpd.exe"?') { $possiblePaths += $matches[1] }
                }

                $cmd = Get-Command httpd.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($cmd) { $possiblePaths += Split-Path -Path (Split-Path -Path $cmd.Definition -Parent) -Parent }

                $uniquePaths = $possiblePaths | Where-Object { $_ } | Select-Object -Unique
                foreach ($p in $uniquePaths) {
                    if (Test-Path "$p\conf\httpd.conf") { $path = $p; break }
                }
                
                if ([string]::IsNullOrEmpty($path) -and $i -eq 0) {
                    Write-LogWarn "Apache no encontrado en rutas conocidas. Reintentando con --force..."
                    choco install apache-httpd --version=$Version -y --no-progress --force | Out-Host
                } else { break }
            }

            if ([string]::IsNullOrEmpty($path)) {
                Write-LogError "No se pudo localizar la instalación de Apache en: $(($possiblePaths | Select-Object -Unique) -join ', '). Revisa el output de Chocolatey arriba."
                return $false
            }
            if ($path -notmatch 'C:\\tools|C:\\Apache24') {
                Write-LogWarn "Aviso: Se detectó Apache en una ruta inusual: $path"
            }

            $conf = "$path\conf\httpd.conf"
            $c = Get-Content $conf -ErrorAction SilentlyContinue
            if ($null -eq $c) { Write-LogError "No se pudo leer el archivo de configuración en $conf."; return $false }
            
            $c = $c -replace '(?mi)^\s*Listen\s+.*', "Listen $Port"
            $c = $c -replace '(?mi)^\s*#?ServerName\s+.*', "ServerName localhost:$Port"
            
            # Asegurar ServerRoot correcto
            $pathFix = $path -replace '\\', '/'
            if ($c -match '(?mi)^\s*#?ServerRoot') {
                $c = $c -replace '(?mi)^\s*#?ServerRoot\s+.*', "ServerRoot `"$pathFix`""
            } else {
                $c = "ServerRoot `"$pathFix`"`r`n$c"
            }

            $c = $c -replace '(?mi)^\s*ServerTokens\s+\w+', "ServerTokens Prod"
            $c | Set-Content $conf
            Set-ServicePermissions -ServiceName "apache" -Path "$path\htdocs"
            Generate-IndexHtml -Path "$path\htdocs\index.html" -Svc "Apache" -Ver $Version -Port $Port
            Write-LogInfo "Reiniciando servicio Apache..."
            Restart-Service Apache* -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            
            $status = Get-Service -Name Apache* -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $status -or $status.Status -ne "Running") {
                Write-LogWarn "El servicio Apache no arrancó o no existe. Intentando arranque directo con -f..."
                Stop-Process -Name httpd -Force -ErrorAction SilentlyContinue
                Start-Process -FilePath "$path\bin\httpd.exe" -ArgumentList "-f `"$conf`"" -WorkingDirectory "$path\bin" -WindowStyle Hidden -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            
            $res = [bool](Test-PortInUse -Port $Port)
            if ($res) {
                Write-LogSuccess "Apache verificado y escuchando en el puerto $Port."
            } else {
                Write-Host "Diagnostic: Checking port $($Port)..." -ForegroundColor Gray
                netstat -ano | Select-String ":$($Port)\s+" | Out-Host

                Write-Host "Comprobando logs en $path\logs..." -ForegroundColor Gray
                $logFile = Join-Path $path "logs\error.log"
                if (-not (Test-Path $logFile)) { $logFile = Join-Path $path "logs\error_log" }
                
                if (Test-Path $logFile) {
                    Get-Content $logFile -Tail 15 | Out-Host
                } else {
                    Write-LogWarn "No se encontró log en $($path)\logs. Listando archivos..."
                    Get-ChildItem "$path" -Recurse -Filter "*log*" -ErrorAction SilentlyContinue | Select -First 5 | FT -Auto | Out-Host
                }
                
                Write-LogInfo "Sugerencia: Intenta ejecutar manualmente para ver errores: & '$path\bin\httpd.exe' -f '$conf'"
            }
            return $res
        }
        default {
            Write-LogError "El servicio '$Service' no es válido o no está soportado. Use: iis, apache, nginx."
            return $false
        }
    }
    Set-HttpFirewallRule -Port $Port -Svc $Service | Out-Null
    return $true 
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
    # 1. Detener y desregistrar servicios conocidos
    $servicesToKill = Get-Service -Name W3SVC, Apache*, nginx* -ErrorAction SilentlyContinue
    foreach ($s in $servicesToKill) {
        Write-LogInfo "Eliminando servicio $($s.Name)..."
        Stop-Service $s.Name -Force -ErrorAction SilentlyContinue | Out-Null
        sc.exe delete $s.Name | Out-Null
    }
    
    # 2. Matar procesos huérfanos (incluyendo posibles hijos)
    Write-LogInfo "Limpiando procesos residuales..."
    Get-Process -Name nginx, httpd, Apache* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # 3. Desinstalar y limpiar carpetas
    Write-LogInfo "Eliminando archivos y características..."
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    choco uninstall nginx apache-httpd -y --remove-dependencies -ErrorAction SilentlyContinue | Out-Host
    
    $cleanPaths = @("C:\tools\nginx*", "C:\tools\apache*", "C:\Apache24", "C:\tools\apache24", "$env:AppData\nginx*", "$env:AppData\Apache*", "$env:LOCALAPPDATA\nginx*", "$env:LOCALAPPDATA\Apache*")
    # Limpiar AppData de todos los usuarios si es posible (solo el actual es seguro)
    foreach ($cp in $cleanPaths) {
        Remove-Item $cp -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Intento extra para la ruta específica reportada por el usuario
    Remove-Item "C:\Users\Administrator\AppData\Roaming\Apache24" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-LogSuccess "Eliminación completada. El sistema está limpio."
    exit 0
}

if ($Service -ne "") {
    $validServices = @("iis", "apache", "nginx")
    if ($validServices -notcontains $Service.ToLower()) {
        Write-LogError "Servicio '$Service' no válido. Use: $($validServices -join ', ')."
        exit 1
    }
    if ($Port -eq 0) { Write-LogError "El parámetro -Port es obligatorio para el modo no interactivo."; exit 1 }
    
    $Version = Get-DynamicVersions -Service $Service | Select-Object -First 1
    if ($null -eq $Version) { $Version = "LTS" }
    
    if (Install-WebServer -Service $Service -Port $Port -Version $Version) {
        Write-LogSuccess "Proceso de despliegue silencioso finalizado correctamente."
        exit 0
    } else {
        Write-LogError "El despliegue silencioso falló."
        exit 1
    }
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
